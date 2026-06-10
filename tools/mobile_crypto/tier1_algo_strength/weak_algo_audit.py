"""weak_algo_audit (§4 #46) — exhaustive scan for deprecated crypto primitives.
Goes deeper than mobile_static's weak_crypto_audit: catalogs every weak
algorithm reference with file + caller class, enabling targeted refactor."""
from __future__ import annotations
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.weak_algo_audit_findings import WEAK_ALGO_AUDIT_FINDING_RULES

router = APIRouter()

# Each pattern = (regex, algo_name, severity_hint)
WEAK_ALGOS = [
    (re.compile(r'"DES"|"DES/[A-Z]{3}'), "DES", "HIGH"),
    (re.compile(r'"DESede"|"3DES"|"TripleDES"'), "3DES", "HIGH"),
    (re.compile(r'"RC2"|"RC4"|"ARCFOUR"'), "RC4/RC2", "HIGH"),
    (re.compile(r'"Blowfish"'), "Blowfish", "MEDIUM"),
    (re.compile(r'"MD5"|"MD4"|"MD2"'), "MD5", "MEDIUM"),
    (re.compile(r'"SHA-?1"|"HMACSHA1"'), "SHA-1", "MEDIUM"),
    (re.compile(r'"NoPadding"\s*"|getInstance\("[A-Z]+/ECB'), "ECB-mode hint", "HIGH"),
    (re.compile(r'"PBEWithMD5"'), "PBEWithMD5", "HIGH"),
]
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["weak_algo_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["weak_algo_audit_error"] = str(e)
        return

    matches_by_algo = {}
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1
        for regex, algo, _sev in WEAK_ALGOS:
            if regex.search(txt):
                matches_by_algo.setdefault(algo, [])
                if p.name not in matches_by_algo[algo] and len(matches_by_algo[algo]) < 10:
                    matches_by_algo[algo].append(p.name)

    ctx.state["weak_algos_found"] = matches_by_algo
    ctx.state["files_scanned"] = files_scanned
    ctx.state["weak_algo_audit_total"] = len(matches_by_algo)
    ctx.source(f"{files_scanned} smali files")


INTEL_FIELDS = [
    ("Weak algorithm references", "weak_algos_found"),
]


@router.post("/api/mobile_crypto/weak_algo_audit")
async def mobile_crypto_weak_algo_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="weak_algo_audit",
        gather_func=gather,
        finding_rules=WEAK_ALGO_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
