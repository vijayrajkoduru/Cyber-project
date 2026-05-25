"""hardcoded_keys_audit (§4 #48) — find hardcoded encryption keys + IVs.
Uses both regex (known formats) AND entropy heuristics (high-entropy
hex/base64 strings of crypto-key length). Industry incidents: Travis,
GitLab, Twilio all leaked keys this way.

False-positive controls:
- KNOWN_PUBLIC_CONSTANTS skips publicly-documented EC curve params, well-
  known protocol moduli, HMAC test vectors. NOT secrets.
- ALLOWLIST_CLASS_PATTERNS skips files implementing standard crypto math
  (Curve25519, P-256/384/521 internals, Tink primitives) — those files
  legitimately contain public constants that look like keys to entropy.
"""
from __future__ import annotations
import math
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.hardcoded_keys_audit_findings import HARDCODED_KEYS_AUDIT_FINDING_RULES

router = APIRouter()

# Patterns: SecretKeySpec/IvParameterSpec called with a literal byte array
KEY_LITERAL_PATTERNS = [
    (re.compile(r'SecretKeySpec.*?"([A-Za-z0-9+/=]{16,80})"'), "SecretKeySpec arg"),
    (re.compile(r'IvParameterSpec.*?"([A-Za-z0-9+/=]{12,40})"'), "IvParameterSpec arg"),
    (re.compile(r'KeyGenerator.*?"([A-Za-z0-9+/=]{16,80})"'), "KeyGenerator init"),
]
# High-entropy literal patterns (hex of 32/48/64 chars = AES-128/192/256)
HEX_KEY_PATTERN = re.compile(r'"([0-9a-fA-F]{32}|[0-9a-fA-F]{48}|[0-9a-fA-F]{64})"')
SCAN_MAX_FILES = 3000

# ─── False-positive allowlists ──────────────────────────────────
# Publicly documented EC curve / protocol constants. Case-insensitive
# substring match against the captured hex literal.
KNOWN_PUBLIC_CONSTANTS = {
    # NIST P-256 (secp256r1)
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",  # p
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",  # n
    "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",  # B
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",  # Gx
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",  # Gy
    # NIST P-384 truncations
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    # secp256k1 (Bitcoin)
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    # Curve25519 base point
    "0900000000000000000000000000000000000000000000000000000000000000",
    # RFC 3526 MODP groups (truncated unique prefixes)
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1",
    # Common test vectors
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "00000000000000000000000000000000",
}
# Class-name patterns whose files legitimately hold curve / protocol math.
# Substring match against the smali file's basename (lowercased).
ALLOWLIST_CLASS_PATTERNS = (
    "ellipticcurve", "ellipticcurves",
    "secp256", "secp384", "secp521", "secp192", "secp224",
    "curve25519", "curve448",
    "p256", "p384", "p521",
    "nistcurves", "namedcurves", "customnamedcurves",
    "x9ecparameters", "x962",
    "rsa2048", "rfc3526", "rfc7919", "diffiehellman", "ffdhe",
    # Tink primitives that ship known reference test vectors
    "hkdf", "hpke", "primefieldelement", "ec5util",
)
# Sub-strings inside the smali path that mean "this is a known library".
ALLOWLIST_PATH_PATTERNS = (
    "/com/google/crypto/tink/",
    "/org/bouncycastle/",
    "/org/conscrypt/",
    "/google/crypto/tink/",
    "/bouncycastle/",
    "/conscrypt/",
)


def _is_known_public_constant(hex_lit: str) -> bool:
    lit_lower = hex_lit.lower()
    return any(known in lit_lower or lit_lower in known
                for known in KNOWN_PUBLIC_CONSTANTS)


def _is_allowlisted_path(smali_path: Path, unpacked_root: Path) -> bool:
    """Match against full path under unpacked APK + class-name basename."""
    name_lower = smali_path.name.lower()
    if any(pat in name_lower for pat in ALLOWLIST_CLASS_PATTERNS):
        return True
    try:
        rel = str(smali_path.relative_to(unpacked_root)).replace("\\", "/").lower()
    except ValueError:
        rel = str(smali_path).lower()
    return any(pat in rel for pat in ALLOWLIST_PATH_PATTERNS)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["hardcoded_keys_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["hardcoded_keys_audit_error"] = str(e)
        return

    matched_keys = []          # known API + literal (always suspect)
    high_entropy_hex = []      # suspected key by entropy
    allowlisted_skipped = 0    # FP-control: count of files / literals skipped
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1

        path_is_allowlisted = _is_allowlisted_path(p, unpacked)

        # API-confirmed keys (SecretKeySpec / IvParameterSpec) — these are ALWAYS
        # suspect regardless of path because they directly initialize keys.
        for regex, label in KEY_LITERAL_PATTERNS:
            for m in regex.finditer(txt):
                lit = m.group(1)
                if _entropy(lit) > 3.5 and len(matched_keys) < 30:
                    matched_keys.append({"file": p.name, "label": label,
                                          "value_preview": lit[:24] + "..."})

        # Entropy-only matches — skip these if the file is in a known crypto
        # library (Tink/BouncyCastle EC curves etc. legitimately hold curve params).
        if path_is_allowlisted:
            allowlisted_skipped += 1
            continue

        for m in HEX_KEY_PATTERN.finditer(txt):
            lit = m.group(1)
            if _is_known_public_constant(lit):
                allowlisted_skipped += 1
                continue
            if _entropy(lit) > 3.5:
                if len(high_entropy_hex) < 20:
                    high_entropy_hex.append({"file": p.name,
                                              "value_preview": lit[:24] + "...",
                                              "length": len(lit)})

    ctx.state["matched_hardcoded_keys"] = matched_keys
    ctx.state["high_entropy_hex_keys"] = high_entropy_hex
    ctx.state["files_scanned"] = files_scanned
    ctx.state["allowlisted_skipped"] = allowlisted_skipped
    ctx.state["hardcoded_keys_audit_total"] = len(matched_keys) + (1 if high_entropy_hex else 0)
    ctx.source(f"{files_scanned} smali files ({allowlisted_skipped} crypto-lib paths allowlisted)")


INTEL_FIELDS = [
    ("API-confirmed hardcoded keys", "matched_hardcoded_keys"),
    ("High-entropy hex literals (likely keys)", "high_entropy_hex_keys"),
]


@router.post("/api/mobile_crypto/hardcoded_keys_audit")
async def mobile_crypto_hardcoded_keys_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="hardcoded_keys_audit",
        gather_func=gather,
        finding_rules=HARDCODED_KEYS_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
