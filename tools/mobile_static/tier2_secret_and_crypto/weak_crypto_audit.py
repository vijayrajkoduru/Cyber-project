"""weak_crypto_audit — detect deprecated cipher primitives + insecure modes."""
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.weak_crypto_audit_findings import WEAK_CRYPTO_AUDIT_FINDING_RULES
from tools._payloads.mobile._loader import load_json

router = APIRouter()

# Patterns based on smali + Java/Kotlin syntax. Sourced from the shared
# AI-curated mobile pool; inline dict is the fallback.
_WEAK_CRYPTO_FALLBACK = {
    "DES cipher":          r'Cipher\.getInstance\(\s*"DES"|/javax/crypto/spec/DESKeySpec|"DES/CBC|"DES/ECB',
    "RC4 cipher":          r'Cipher\.getInstance\(\s*"RC4"|"ARC4"',
    "Blowfish cipher":     r'Cipher\.getInstance\(\s*"Blowfish"',
    "AES ECB mode":        r'Cipher\.getInstance\(\s*"AES/ECB',
    "MD5 used for crypto": r'MessageDigest\.getInstance\(\s*"MD5"|/MD5\.smali',
    "SHA1 used for crypto":r'MessageDigest\.getInstance\(\s*"SHA-?1"|/SHA1\.smali',
    "Insecure SecureRandom seed": r'SecureRandom\(\)\.setSeed\(|new SecureRandom\(new byte',
    "TrustManager bypass": r'X509TrustManager.{1,500}checkServerTrusted[^{]*\{\s*\}|return\s+new\s+X509Certificate\[\s*0\s*\]',
    "HostnameVerifier ALLOW_ALL": r'ALLOW_ALL_HOSTNAME_VERIFIER|verify\s*\([^)]*\)\s*\{\s*return\s+true',
}
PATTERNS = {
    name: re.compile(rx)
    for name, rx in load_json("weak_crypto", fallback=_WEAK_CRYPTO_FALLBACK).items()
    if name != "_note"
}

SCAN_EXTS = (".java", ".kt", ".smali")


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["weak_crypto_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["weak_crypto_audit_error"] = str(e)
        return

    hits = []
    files_scanned = 0
    for f in unpacked.rglob("*"):
        if not f.is_file() or f.suffix.lower() not in SCAN_EXTS:
            continue
        if files_scanned >= 5000:
            break
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        files_scanned += 1
        for kind, pat in PATTERNS.items():
            for m in pat.finditer(text):
                hits.append({
                    "kind": kind,
                    "file": str(f.relative_to(unpacked))[:120],
                    "snippet": m.group(0)[:80],
                })
                if len(hits) >= 200:
                    break
            if len(hits) >= 200:
                break
        if len(hits) >= 200:
            break

    ctx.state["crypto_issues"] = hits
    ctx.state["weak_crypto_audit_total"] = len(hits)
    ctx.state["files_scanned"] = files_scanned
    ctx.source(f"crypto-pattern-scan ({files_scanned} files)")


INTEL_FIELDS = [
    ("Crypto issues", "weak_crypto_audit_total"),
]


@router.post("/api/mobile_static/weak_crypto_audit")
async def mobile_static_weak_crypto_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="weak_crypto_audit",
        gather_func=gather,
        finding_rules=WEAK_CRYPTO_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
