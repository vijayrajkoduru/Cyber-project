"""image_cache_paths_audit — detect hardcoded paths suggesting image / video
cache stored in unsafe locations (world-readable /sdcard, no encryption).
Common offenders: Glide / Picasso / Fresco / ExoPlayer custom dirs."""
from __future__ import annotations
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.image_cache_paths_audit_findings import IMAGE_CACHE_PATHS_AUDIT_FINDING_RULES

router = APIRouter()

UNSAFE_PATH_RE = re.compile(
    r'"(/sdcard/[^"]*|/storage/emulated/[^"]*|Environment\.getExternalStorageDirectory)"',
    re.IGNORECASE)
CACHE_LIB_HINTS = ("Glide", "Picasso", "Fresco", "ExoPlayer", "coil")
SCAN_MAX_FILES = 2500


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["image_cache_paths_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["image_cache_paths_audit_error"] = str(e)
        return

    unsafe_paths = []
    cache_lib_hits = []
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1

        for m in UNSAFE_PATH_RE.finditer(txt):
            path = m.group(1)
            if path not in unsafe_paths and len(unsafe_paths) < 40:
                unsafe_paths.append(path)

        for lib in CACHE_LIB_HINTS:
            if lib in txt and lib not in cache_lib_hits:
                cache_lib_hits.append(lib)

    ctx.state["unsafe_paths"] = unsafe_paths
    ctx.state["cache_libs"] = cache_lib_hits
    ctx.state["files_scanned"] = files_scanned
    ctx.state["image_cache_paths_audit_total"] = len(unsafe_paths)
    ctx.source(f"{files_scanned} smali files")


INTEL_FIELDS = [
    ("Unsafe external paths", "unsafe_paths"),
    ("Cache libs detected", "cache_libs"),
]


@router.post("/api/mobile_storage/image_cache_paths_audit")
async def mobile_storage_image_cache_paths_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="image_cache_paths_audit",
        gather_func=gather,
        finding_rules=IMAGE_CACHE_PATHS_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
