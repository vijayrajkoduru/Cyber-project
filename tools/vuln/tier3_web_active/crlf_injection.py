"""CRLF Injection - passive header-injection detection. Self-contained.
Strategy: inject %0d%0aSet-Cookie:vlcrlf=1 in common params, check response headers
for the injected header appearing in server reply."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url, http_get

router = APIRouter()

INJECT = "test%0d%0aSet-Cookie:%20vlcrlf=1"
MARKER_HEADER = "vlcrlf"
PROBE_PARAMS = ["url", "redirect", "next", "q", "page", "lang"]


async def gather(ctx):
    host = str(ctx.host)
    base_url, base = probe_url(host, "/")
    if not base:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    ctx.state["probed_params"] = len(PROBE_PARAMS)
    hits = []
    for p in PROBE_PARAMS:
        url = f"{base_url}?{p}={INJECT}"
        r = http_get(url, timeout=8)
        if not r:
            continue
        # Check both response headers + Set-Cookie for the injected marker
        for hn, hv in (r.get("headers") or {}).items():
            if MARKER_HEADER in str(hv).lower():
                hits.append({"param": p, "header": hn, "value": str(hv)[:80]})
                break
    ctx.state["crlf_hits"] = hits


def _r_crlf(s):
    hits = s.get("crlf_hits") or []
    if not hits:
        return None
    return {"name": f"CRLF / header injection observed in {len(hits)} parameter(s)", "severity": "HIGH", "cvss": 7.4,
            "cwe": "CWE-93",
            "evidence": "; ".join(f"{h['param']} -> {h['header']}" for h in hits),
            "remediation": "Reject CR (\\r 0x0d) and LF (\\n 0x0a) in any value that builds HTTP response headers."}


FINDING_RULES = [_r_crlf]
INTEL_FIELDS = [("Parameters probed", "probed_params"), ("CRLF hits", "crlf_hits")]


@router.post("/api/vuln/crlf_injection")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="crlf_injection",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
