"""play_integrity_audit — detect Play Integrity API / SafetyNet usage.
Modern apps SHOULD use Play Integrity (replaces SafetyNet 2024+) for
hardware-backed device attestation. Absence = no anti-rooting at the
server level."""
from __future__ import annotations
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.play_integrity_audit_findings import PLAY_INTEGRITY_AUDIT_FINDING_RULES

router = APIRouter()

ATTESTATION_MARKERS = {
    "Play Integrity API (current)": [
        "com/google/android/play/core/integrity",
        "IntegrityManager", "IntegrityTokenRequest",
        "IntegrityManagerFactory", "StandardIntegrityManager",
    ],
    "SafetyNet (deprecated, EOL 2024)": [
        "com/google/android/gms/safetynet/SafetyNetClient",
        "SafetyNet.getClient", "SafetyNetApi",
        "AttestationResponse",
    ],
    "Hardware Key Attestation": [
        "KeyGenParameterSpec", "setAttestationChallenge",
        "android/security/keystore",
    ],
    "Firebase App Check": [
        "com/google/firebase/appcheck",
        "FirebaseAppCheck", "PlayIntegrityAppCheckProviderFactory",
    ],
}
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["play_integrity_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["play_integrity_audit_error"] = str(e)
        return

    mechanisms = {}
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1
        for mech_name, markers in ATTESTATION_MARKERS.items():
            for m in markers:
                if m in txt:
                    mechanisms.setdefault(mech_name, [])
                    if len(mechanisms[mech_name]) < 5 and p.name not in mechanisms[mech_name]:
                        mechanisms[mech_name].append(p.name)
                    break

    has_modern = "Play Integrity API (current)" in mechanisms
    has_deprecated = "SafetyNet (deprecated, EOL 2024)" in mechanisms
    ctx.state["attestation_mechanisms"] = mechanisms
    ctx.state["has_play_integrity"] = has_modern
    ctx.state["has_deprecated_safetynet"] = has_deprecated
    ctx.state["files_scanned"] = files_scanned
    # Findings: presence of any attestation = good; missing entirely = info-level gap
    ctx.state["play_integrity_audit_total"] = len(mechanisms)
    ctx.source(f"{files_scanned} smali files")


INTEL_FIELDS = [
    ("Attestation mechanisms found", "attestation_mechanisms"),
    ("Uses Play Integrity (modern)", "has_play_integrity"),
    ("Uses deprecated SafetyNet", "has_deprecated_safetynet"),
]


@router.post("/api/mobile_runtime/play_integrity_audit")
async def mobile_runtime_play_integrity_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="play_integrity_audit",
        gather_func=gather,
        finding_rules=PLAY_INTEGRITY_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
