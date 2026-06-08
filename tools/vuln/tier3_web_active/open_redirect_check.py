"""Open Redirect - passive Location-header redirect check. Self-contained.
Strategy: probe target with url=/redirect=/next=/return= params pointing to external
domain, check if Location header reflects the external domain."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url, http_get

router = APIRouter()

REDIRECT_PAYLOAD = "https://example.org/"
PROBE_PARAMS = ["url", "redirect", "redirect_uri", "next", "return", "returnTo",
                "continue", "goto", "destination", "out", "to", "target"]


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
        url = f"{base_url}?{p}={REDIRECT_PAYLOAD}"
        r = http_get(url, timeout=8)
        if not r:
            continue
        loc = (r.get("headers") or {}).get("location", "") or ""
        if "example.org" in loc.lower():
            hits.append({"param": p, "location": loc[:120], "status": r.get("status")})
    ctx.state["redirect_hits"] = hits


def _r_redir(s):
    hits = s.get("redirect_hits") or []
    if not hits:
        return None
    return {"name": f"Open redirect in {len(hits)} parameter(s)", "severity": "MEDIUM", "cvss": 6.1,
            "cwe": "CWE-601",
            "evidence": "Server issues redirect to attacker-controlled URL for: " + ", ".join(h["param"] for h in hits),
            "remediation": "Validate redirect target against an allow-list. Reject schemes != https + hosts not in your domain."}


FINDING_RULES = [_r_redir]
INTEL_FIELDS = [("Parameters probed", "probed_params"), ("Redirect hits", "redirect_hits")]


@router.post("/api/vuln/open_redirect_check")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="open_redirect_check",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
