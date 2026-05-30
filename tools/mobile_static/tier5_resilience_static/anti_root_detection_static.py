"""anti_root_detection_static — static markers for root/jailbreak detection.

Scans the unpacked APK/IPA for known root-detection library signatures
and code patterns (RootBeer, SafetyNet/Play Integrity, Magisk-detect
strings). Apps targeting financial / health / IP-protected verticals
SHOULD have these. Apps that DON'T are easier targets for rooted-device
runtime attacks (Frida injection, certificate-pinning bypass).

MASVS-RESILIENCE-1 / MSTG-RESILIENCE-1.
"""
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.anti_root_detection_static_findings import \
    ANTI_ROOT_DETECTION_STATIC_FINDING_RULES

router = APIRouter()

ROOT_MARKERS = [
    # Known libraries
    "com/scottyab/rootbeer", "com.scottyab.rootbeer",
    "io/github/asuhsa/rootbeer", "RootBeer",
    # Common root-binary path strings
    "/system/app/Superuser.apk", "/system/xbin/su", "/system/bin/su",
    "/sbin/su", "/system/sd/xbin/su",
    "com.koushikdutta.superuser", "eu.chainfire.supersu",
    "com.noshufou.android.su", "com.thirdparty.superuser",
    "com.topjohnwu.magisk", "io.github.huskydg.magisk",
    "/data/adb/magisk", "MagiskHide",
    # Play Integrity / SafetyNet
    "com.google.android.play.core.integrity",
    "PlayIntegrityManager", "IntegrityTokenRequest",
    "com.google.android.gms.safetynet", "SafetyNetClient",
    # iOS jailbreak markers (for IPA inputs)
    "/Applications/Cydia.app", "/Library/MobileSubstrate",
    "/bin/bash", "/usr/sbin/sshd", "/etc/apt",
    "Frida-detect", "frida-gum",
]


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["anti_root_detection_static_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["anti_root_detection_static_error"] = str(e); return

    matched = []
    files_scanned = 0
    for f in unpacked.rglob("*"):
        if not f.is_file(): continue
        if f.suffix not in (".dex", ".so", ".smali", ".xml", ".plist", ".json"):
            # Also scan strings out of any classes.dex variants
            if "classes" not in f.name: continue
        try:
            data = f.read_bytes()[:5_000_000]
        except Exception: continue
        files_scanned += 1
        for marker in ROOT_MARKERS:
            if marker.encode() in data:
                matched.append({"marker": marker, "file": f.relative_to(unpacked).as_posix()})
                if len(matched) > 30: break
        if len(matched) > 30: break

    ctx.state["root_detection_markers_found"] = matched
    ctx.state["anti_root_detection_static_total"] = len(matched)
    ctx.state["files_scanned"] = files_scanned
    ctx.source(f"scanned {files_scanned} files")


INTEL_FIELDS = [
    ("Root-detection markers found", "anti_root_detection_static_total"),
    ("Files scanned",                "files_scanned"),
]


@router.post("/api/mobile_static/anti_root_detection_static")
async def mobile_static_anti_root_detection_static(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="anti_root_detection_static",
        gather_func=gather,
        finding_rules=ANTI_ROOT_DETECTION_STATIC_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
