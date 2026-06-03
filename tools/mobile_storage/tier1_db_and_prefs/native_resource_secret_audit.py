"""native_resource_secret_audit - secrets baked in .so / .dylib strings.
Mobile devs sometimes hide API keys by moving them into NDK and storing
as a global string. `strings libfoo.so` recovers them in seconds. Catches
high-entropy / key-shaped tokens inside native binaries. MSTG-STORAGE-1."""
from __future__ import annotations
import re
import math
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.native_resource_secret_audit_findings import NATIVE_RESOURCE_SECRET_AUDIT_FINDING_RULES

router = APIRouter()
KEY_PATTERN_RE = re.compile(
    rb'(AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{20,}|ghp_[A-Za-z0-9]{36}|'
    rb'AIza[0-9A-Za-z\-_]{35}|eyJ[A-Za-z0-9\-_=]{20,}\.[A-Za-z0-9\-_=]{20,}\.[A-Za-z0-9\-_.+/=]+)'
)
GENERIC_TOKEN_RE = re.compile(rb'(?:api[_-]?key|secret|token|bearer)["\'=:\s]+([A-Za-z0-9\-_]{20,80})', re.IGNORECASE)


def _shannon(b: bytes) -> float:
    if not b: return 0.0
    freq = {}
    for x in b: freq[x] = freq.get(x, 0) + 1
    total = len(b)
    return -sum((c/total) * math.log2(c/total) for c in freq.values())


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["native_resource_secret_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["native_resource_secret_audit_error"] = str(e); return
    libs_scanned = 0
    pattern_hits = []
    high_entropy_hits = []
    for p in unpacked.rglob("*"):
        if libs_scanned >= 30: break
        if not p.is_file(): continue
        if p.suffix not in (".so", ".dylib"): continue
        try: blob = p.read_bytes()[:8_000_000]  # cap 8 MB per lib
        except OSError: continue
        libs_scanned += 1
        for m in KEY_PATTERN_RE.finditer(blob):
            if len(pattern_hits) < 25:
                pattern_hits.append({"lib": p.name, "match": m.group(0).decode("utf-8", "ignore")[:50]})
        for m in GENERIC_TOKEN_RE.finditer(blob):
            tok = m.group(1)
            if len(tok) >= 24 and _shannon(tok) >= 3.5:
                if len(high_entropy_hits) < 25:
                    high_entropy_hits.append({"lib": p.name, "preview": tok.decode("utf-8", "ignore")[:50]})
    findings_total = 0
    if pattern_hits:
        findings_total += 1
    if high_entropy_hits:
        findings_total += 1
    ctx.state["pattern_hits"] = pattern_hits
    ctx.state["high_entropy_hits"] = high_entropy_hits
    ctx.state["libs_scanned"] = libs_scanned
    ctx.state["native_resource_secret_audit_total"] = findings_total
    ctx.source(f"{libs_scanned} native libs")


INTEL_FIELDS = [("Vendor key patterns", "pattern_hits"),
                ("High-entropy token hits", "high_entropy_hits"),
                ("Libs scanned", "libs_scanned")]


@router.post("/api/mobile_storage/native_resource_secret_audit")
async def mobile_storage_native_resource_secret_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="native_resource_secret_audit",
        gather_func=gather, finding_rules=NATIVE_RESOURCE_SECRET_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
