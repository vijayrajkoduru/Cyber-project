"""external_storage_audit — manifest + code audit for SD-card / external
storage access. Flags: WRITE_EXTERNAL_STORAGE/READ_EXTERNAL_STORAGE perms,
hardcoded paths under /sdcard or /storage/emulated, MediaStore writes
without scoped-storage policy."""
from __future__ import annotations
import re
from pathlib import Path
from xml.etree import ElementTree as ET

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.external_storage_audit_findings import EXTERNAL_STORAGE_AUDIT_FINDING_RULES

router = APIRouter()

NS = {"a": "http://schemas.android.com/apk/res/android"}
EXTERNAL_PATH_RE = re.compile(
    r'"(/sdcard/[^"]*|/storage/emulated/[^"]*|/storage/[^"]*sdcard[^"]*)"')
EXT_STORAGE_PERMS = (
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
)
SCAN_MAX_FILES = 2500


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["external_storage_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["external_storage_audit_error"] = str(e)
        return

    # Manifest: external-storage perms
    perms_requested = []
    target_sdk = None
    manifest = unpacked / "AndroidManifest.xml"
    if manifest.is_file():
        try:
            root = ET.parse(str(manifest)).getroot()
            for p in root.findall("uses-permission"):
                name = p.get(f"{{{NS['a']}}}name", "")
                if name in EXT_STORAGE_PERMS:
                    perms_requested.append(name)
            usdk = root.find("uses-sdk")
            if usdk is not None:
                target_sdk = usdk.get(f"{{{NS['a']}}}targetSdkVersion")
        except ET.ParseError:
            pass

    # Code: hardcoded external paths
    hardcoded_paths = []
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1
        for m in EXTERNAL_PATH_RE.finditer(txt):
            path = m.group(1)
            if path not in hardcoded_paths and len(hardcoded_paths) < 30:
                hardcoded_paths.append(path)

    findings_total = 0
    if perms_requested:
        findings_total += 1
    if hardcoded_paths:
        findings_total += 1

    ctx.state["external_perms"] = perms_requested
    ctx.state["hardcoded_external_paths"] = hardcoded_paths
    ctx.state["target_sdk"] = target_sdk
    ctx.state["files_scanned"] = files_scanned
    ctx.state["external_storage_audit_total"] = findings_total
    ctx.source(f"manifest + {files_scanned} smali files")


INTEL_FIELDS = [
    ("External-storage permissions", "external_perms"),
    ("Hardcoded external paths", "hardcoded_external_paths"),
    ("targetSdkVersion", "target_sdk"),
]


@router.post("/api/mobile_storage/external_storage_audit")
async def mobile_storage_external_storage_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="external_storage_audit",
        gather_func=gather,
        finding_rules=EXTERNAL_STORAGE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
