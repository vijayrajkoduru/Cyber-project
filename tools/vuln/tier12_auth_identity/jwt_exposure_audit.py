"""JWT exposure + weak algorithm audit (alg:none / HS / no-exp). VL-FORGE Vuln tier12 - §12 #175.

VL-VERIFY: SPA bundles can carry example JWTs (CodeMirror / jwt.io demo
tokens, JWT-decoder samples, GraphQL playground fixtures) that match the
eyJ.eyJ regex but aren't real secrets. The SPA canary returns the same
bundle for every URL; any JWT that ALSO appears in the canary body is a
bundle-static token, not a real exposed credential. We drop those.
"""
import asyncio
import base64
import json
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._vl_core import run_scanner
from tools.vuln._vuln_common import http_get, detect_spa_catchall

router = APIRouter()
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*")


def _b64(seg):
    seg += "=" * (-len(seg) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(seg))
    except Exception:
        return {}


async def gather(ctx):
    base = web_url(str(ctx.host)).rstrip("/")
    # VL-VERIFY canary
    spa = await detect_spa_catchall(base)
    ctx.state["spa_catchall"] = spa.get("is_spa", False)
    canary_body = spa.get("canary_body", "") or ""
    r = await asyncio.to_thread(http_get, base + "/", 10, 200000)
    if not r:
        ctx.state["tested"] = 0
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    blob = (r.get("body", "") or "") + " " + " ".join(f"{k}:{v}" for k, v in (r.get("headers") or {}).items())
    raw_toks = _JWT.findall(blob)
    # SPA suppression - drop any JWT that also appears in the SPA canary
    if spa.get("is_spa") and canary_body:
        kept, suppressed = [], []
        for t in raw_toks:
            if t in canary_body:
                suppressed.append(t[:12] + "...")
            else:
                kept.append(t)
        toks = kept
        if suppressed:
            ctx.state["jwt_spa_suppressed"] = suppressed[:5]
    else:
        toks = raw_toks
    if not toks:
        return
    ctx.state["jwt_found"] = len(toks)
    weak = []
    for t in toks[:5]:
        parts = t.split(".")
        hdr = _b64(parts[0])
        alg = str(hdr.get("alg", "")).lower()
        if alg in ("none", ""):
            weak.append("alg=none")
        elif alg.startswith("hs"):
            weak.append(f"alg={hdr.get('alg')} (symmetric - crackable if weak secret)")
        if len(parts) > 1 and "exp" not in _b64(parts[1]):
            weak.append("no exp claim")
    if weak:
        ctx.state["jwt_weak"] = list(dict.fromkeys(weak))


def _r_weak(s):
    w = s.get("jwt_weak") or []
    if not w:
        return None
    crit = "alg=none" in " ".join(w)
    return {"name": "JWT with weak configuration exposed", "severity": "HIGH" if crit else "MEDIUM",
            "cvss": 7.5 if crit else 5.3, "cwe": "CWE-347", "evidence": "; ".join(w),
            "remediation": "Use RS256/ES256; reject alg:none; set short exp; verify signature server-side."}


def _r_found(s):
    if not s.get("jwt_found") or s.get("jwt_weak"):
        return None
    return {"name": "JWT exposed in client-visible response", "severity": "LOW", "cwe": "CWE-200",
            "evidence": f"{s.get('jwt_found')} JWT(s) in response/headers",
            "remediation": "Avoid exposing JWTs in HTML/JS; store in HttpOnly cookies."}


def _r_clean(s):
    if (s.get("tested") or 0) < 1 or s.get("jwt_found"):
        return None
    return {"name": "No exposed JWT detected", "severity": "POSITIVE",
            "evidence": "No JWT in homepage response/headers."}


FINDING_RULES = [_r_weak, _r_found, _r_clean]
INTEL_FIELDS = [("JWTs found", "jwt_found")]


@router.post("/api/vuln/jwt_exposure_audit")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="jwt_exposure_audit",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
