"""insecure_prng_audit (§4 #49) — detect java.util.Random in security
contexts. java.util.Random is predictable (LCG). Use SecureRandom for
keys/IVs/nonces/tokens. Math.random() = also predictable."""
from __future__ import annotations
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.insecure_prng_audit_findings import INSECURE_PRNG_AUDIT_FINDING_RULES
from tools._payloads.mobile._loader import load_json

router = APIRouter()

# Markers sourced from the shared AI-curated mobile pool; inline tuple is the
# fallback so behaviour is identical if the JSON is unavailable.
_INSECURE_PRNG_FALLBACK = ("java/util/Random;-><init>", "Math;->random()D")
INSECURE_PRNG_MARKERS = tuple(
    load_json("insecure_prng", fallback={}).get(
        "insecure_markers", _INSECURE_PRNG_FALLBACK)
) or _INSECURE_PRNG_FALLBACK
SECURE_PRNG_MARKER = "java/security/SecureRandom"
SECURITY_CONTEXT_HINTS = ("token", "key", "iv", "nonce", "session",
                          "secret", "password", "auth", "challenge", "salt")
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["insecure_prng_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["insecure_prng_audit_error"] = str(e)
        return

    insecure_files = []
    secure_files = []
    suspicious_in_security_context = []
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1

        is_security_class = any(h in p.name.lower() for h in SECURITY_CONTEXT_HINTS)
        uses_insecure = any(m in txt for m in INSECURE_PRNG_MARKERS)
        uses_secure = SECURE_PRNG_MARKER in txt

        if uses_insecure:
            if len(insecure_files) < 30 and p.name not in insecure_files:
                insecure_files.append(p.name)
            if is_security_class and p.name not in suspicious_in_security_context:
                suspicious_in_security_context.append(p.name)
        if uses_secure and p.name not in secure_files and len(secure_files) < 30:
            secure_files.append(p.name)

    ctx.state["insecure_prng_files"] = insecure_files
    ctx.state["secure_prng_files"] = secure_files
    ctx.state["security_context_insecure"] = suspicious_in_security_context
    ctx.state["files_scanned"] = files_scanned
    ctx.state["insecure_prng_audit_total"] = (
        len(suspicious_in_security_context) or (1 if insecure_files else 0))
    ctx.source(f"{files_scanned} smali files")


INTEL_FIELDS = [
    ("Insecure PRNG (Random / Math.random) callers", "insecure_prng_files"),
    ("Secure PRNG callers", "secure_prng_files"),
    ("Insecure PRNG in security-named class", "security_context_insecure"),
]


@router.post("/api/mobile_crypto/insecure_prng_audit")
async def mobile_crypto_insecure_prng_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="insecure_prng_audit",
        gather_func=gather,
        finding_rules=INSECURE_PRNG_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
