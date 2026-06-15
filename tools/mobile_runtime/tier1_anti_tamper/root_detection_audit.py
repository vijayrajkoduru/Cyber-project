"""root_detection_audit — static detection of root-checking code.
Catalogs WHICH root-detection libraries / patterns the app uses so the
customer can target their manual bypass (Frida CodeShare scripts).
Industry standard: RootBeer is the most common but trivially bypassable."""
from __future__ import annotations
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.root_detection_audit_findings import ROOT_DETECTION_AUDIT_FINDING_RULES
from tools._payloads.mobile._loader import load_json

router = APIRouter()

# Root/jailbreak detection mechanism markers sourced from the shared
# AI-curated mobile pool; inline dict is the fallback.
_ROOT_MARKERS_FALLBACK = {
    "RootBeer (com.scottyab.rootbeer)": ["com/scottyab/rootbeer", "RootBeer", "isRooted"],
    "su binary path checks":            ['"/system/xbin/su"', '"/system/bin/su"', '"/sbin/su"', '"/system/app/Superuser.apk"'],
    "Magisk markers":                   ["Magisk", "/sbin/.magisk", "MagiskHide", "magiskhide"],
    "SuperSU markers":                  ["SuperSU.apk", "eu/chainfire/supersu"],
    "test-keys build tag":              ['"test-keys"'],
    "Superuser package check":          ['"com.koushikdutta.superuser"', '"eu.chainfire.supersu"', '"com.topjohnwu.magisk"'],
    "BusyBox marker":                   ['"busybox"', '"/system/xbin/busybox"'],
}
ROOT_MARKERS = load_json("root_markers", fallback=_ROOT_MARKERS_FALLBACK) \
    or _ROOT_MARKERS_FALLBACK
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["root_detection_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["root_detection_audit_error"] = str(e)
        return

    mechanisms_found = {}
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1
        for mech_name, markers in ROOT_MARKERS.items():
            for m in markers:
                if m in txt:
                    mechanisms_found.setdefault(mech_name, [])
                    if len(mechanisms_found[mech_name]) < 5 and p.name not in mechanisms_found[mech_name]:
                        mechanisms_found[mech_name].append(p.name)
                    break

    ctx.state["root_detection_mechanisms"] = mechanisms_found
    ctx.state["files_scanned"] = files_scanned
    ctx.state["root_detection_audit_total"] = len(mechanisms_found)
    ctx.source(f"{files_scanned} smali files")


INTEL_FIELDS = [
    ("Root-detection mechanisms", "root_detection_mechanisms"),
]


@router.post("/api/mobile_runtime/root_detection_audit")
async def mobile_runtime_root_detection_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="root_detection_audit",
        gather_func=gather,
        finding_rules=ROOT_DETECTION_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
