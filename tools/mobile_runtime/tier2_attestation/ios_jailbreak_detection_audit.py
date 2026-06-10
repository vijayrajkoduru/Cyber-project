"""ios_jailbreak_detection_audit — for IPA files, detect jailbreak-detection
strings + API patterns. Most apps check for /Applications/Cydia,
fork() return value, dyld_get_image_name for known tweak dylibs.
Bypassable with Liberty Lite / A-Bypass / Frida ssl-kill-switch."""
from __future__ import annotations
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.ios_jailbreak_detection_audit_findings import IOS_JAILBREAK_DETECTION_AUDIT_FINDING_RULES

router = APIRouter()

# These markers appear inside the iOS Mach-O binary string table.
JAILBREAK_MARKERS = {
    "Cydia.app filesystem check": [b"/Applications/Cydia.app", b"cydia://"],
    "apt/dpkg filesystem check": [b"/private/var/lib/apt", b"/private/var/lib/dpkg",
                                    b"/var/cache/apt", b"/var/lib/dpkg"],
    "SSH presence check":         [b"/usr/sbin/sshd", b"/etc/ssh"],
    "MobileSubstrate check":      [b"/Library/MobileSubstrate",
                                    b"DynamicLibraries/MobileSubstrate"],
    "Bash / sh binary check":     [b"/bin/bash", b"/bin/sh"],
    "fork() bypass check":        [b"fork", b"vfork"],
    "dyld inspection":            [b"_dyld_get_image_name", b"_dyld_image_count"],
    "Cydia Substrate / Substitute": [b"libsubstitute", b"CydiaSubstrate", b"Substitute"],
}
SCAN_MAX_FILES = 30  # iOS binaries are heavy


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["ios_jailbreak_detection_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["ios_jailbreak_detection_audit_error"] = str(e)
        return

    # Mach-O binaries are inside Payload/<App>.app/<binary>
    mechanisms = {}
    binaries_scanned = 0
    candidates = list(unpacked.rglob("Payload/*.app/*"))
    if not candidates:
        ctx.state["ios_jailbreak_detection_audit_total"] = 0
        ctx.source("no Mach-O binary - probably not an IPA")
        return

    for binary in candidates[:SCAN_MAX_FILES]:
        if not binary.is_file() or binary.suffix in (".plist", ".png", ".jpg", ".storyboardc"):
            continue
        try:
            data = binary.read_bytes()
        except OSError:
            continue
        # Confirm Mach-O magic
        if not (data.startswith(b"\xcf\xfa\xed\xfe") or
                data.startswith(b"\xfe\xed\xfa\xcf") or
                data.startswith(b"\xca\xfe\xba\xbe")):
            continue
        binaries_scanned += 1
        for mech_name, markers in JAILBREAK_MARKERS.items():
            for m in markers:
                if m in data:
                    mechanisms.setdefault(mech_name, [])
                    if len(mechanisms[mech_name]) < 5 and binary.name not in mechanisms[mech_name]:
                        mechanisms[mech_name].append(binary.name)
                    break

    if binaries_scanned == 0:
        ctx.state["ios_jailbreak_detection_audit_total"] = 0
        ctx.source("no Mach-O binaries scanned - probably not an IPA")
        return

    ctx.state["jailbreak_mechanisms"] = mechanisms
    ctx.state["binaries_scanned"] = binaries_scanned
    ctx.state["ios_jailbreak_detection_audit_total"] = len(mechanisms)
    ctx.source(f"{binaries_scanned} Mach-O binaries")


INTEL_FIELDS = [
    ("Mach-O binaries scanned", "binaries_scanned"),
    ("Jailbreak-detection mechanisms", "jailbreak_mechanisms"),
]


@router.post("/api/mobile_runtime/ios_jailbreak_detection_audit")
async def mobile_runtime_ios_jailbreak_detection_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="ios_jailbreak_detection_audit",
        gather_func=gather,
        finding_rules=IOS_JAILBREAK_DETECTION_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
