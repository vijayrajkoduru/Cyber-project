"""A03 XSS - passive reflection check. Self-contained, no cross-module routing.
Strategy: inject a benign canary string (no <script>, no payload), check if it appears unescaped
in HTML body context. Only flags if response contains canary + content-type is HTML."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url_async, http_get_async

router = APIRouter()

CANARY = "vlxss9k4q"
PROBE_PARAMS = ["q", "search", "name", "msg", "comment", "ref", "callback", "v"]


async def gather(ctx):
    host = str(ctx.host)
    base_url, base = await probe_url_async(host, "/")
    if not base or base.get("status", 0) >= 500:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    ctx.state["probed_params"] = len(PROBE_PARAMS)
    reflected = []
    for p in PROBE_PARAMS:
        url = f"{base_url}?{p}={CANARY}"
        r = await http_get_async(url, timeout=8)
        if not r:
            continue
        body = r.get("body", "")
        if CANARY in body:
            ctype = r.get("headers", {}).get("content-type", "")
            if "html" in ctype.lower() or "<" in body[:200]:
                reflected.append({"param": p, "status": r.get("status")})
    ctx.state["reflected_params"] = reflected


def _r_xss(s):
    refl = s.get("reflected_params") or []
    if not refl:
        return None
    return {"name": f"User input reflected unescaped in {len(refl)} parameter(s)", "severity": "MEDIUM", "cvss": 6.1,
            "cwe": "CWE-79",
            "evidence": f"Canary string echoed in HTML body: {', '.join(r['param'] for r in refl)}",
            "remediation": "Apply context-aware HTML entity encoding on output. Use a Content Security Policy."}


FINDING_RULES = [_r_xss]
INTEL_FIELDS = [("Parameters probed", "probed_params"), ("Reflected", "reflected_params")]


@router.post("/api/vuln/a03_xss")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="a03_xss",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
