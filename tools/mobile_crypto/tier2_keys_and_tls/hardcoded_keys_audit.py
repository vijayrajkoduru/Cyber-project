"""hardcoded_keys_audit (§4 #48) — find hardcoded encryption keys + IVs.
Uses both regex (known formats) AND entropy heuristics (high-entropy
hex/base64 strings of crypto-key length). Industry incidents: Travis,
GitLab, Twilio all leaked keys this way."""
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

    matched_keys = []      # known API + literal
    high_entropy_hex = []  # suspected key by entropy
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1

        for regex, label in KEY_LITERAL_PATTERNS:
            for m in regex.finditer(txt):
                lit = m.group(1)
                if _entropy(lit) > 3.5 and len(matched_keys) < 30:
                    matched_keys.append({"file": p.name, "label": label,
                                          "value_preview": lit[:24] + "..."})

        for m in HEX_KEY_PATTERN.finditer(txt):
            lit = m.group(1)
            if _entropy(lit) > 3.5:
                if len(high_entropy_hex) < 20:
                    high_entropy_hex.append({"file": p.name,
                                              "value_preview": lit[:24] + "...",
                                              "length": len(lit)})

    ctx.state["matched_hardcoded_keys"] = matched_keys
    ctx.state["high_entropy_hex_keys"] = high_entropy_hex
    ctx.state["files_scanned"] = files_scanned
    ctx.state["hardcoded_keys_audit_total"] = len(matched_keys) + (1 if high_entropy_hex else 0)
    ctx.source(f"{files_scanned} smali files")


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
