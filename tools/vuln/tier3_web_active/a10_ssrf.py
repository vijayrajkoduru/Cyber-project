"""A10 SSRF - passive open-URL-parameter detection. Self-contained.
Strategy: probe target with url=/redirect=/next=/proxy= params pointing to a public
benign URL (no internal probing!). Check response delta vs control. Conservative."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url, http_get

router = APIRouter()

SSRF_PARAMS = ["url", "u", "redirect", "next", "callback", "proxy", "fetch", "load", "image"]
CONTROL_PAYLOAD = "https://example.org/"  # safe public RFC reservation
INDICATORS = ["example domain", "<title>example domain", "iana"]  # text from example.org


async def gather(ctx):
    host = str(ctx.host)
    base_url, base = probe_url(host, "/")
    if not base:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    ctx.state["probed_params"] = len(SSRF_PARAMS)
    suspects = []
    for p in SSRF_PARAMS:
        url = f"{base_url}?{p}={CONTROL_PAYLOAD}"
        r = http_get(url, timeout=10, read=8000)
        if not r:
            continue
        body_lower = r.get("body", "").lower()
        # If response contains example.org's content, the server fetched it
        if any(ind in body_lower for ind in INDICATORS):
            suspects.append({"param": p, "status": r.get("status")})
    ctx.state["ssrf_suspects"] = suspects


def _r_ssrf(s):
    sus = s.get("ssrf_suspects") or []
    if not sus:
        return None
    return {"name": f"Server-side URL fetch detected in {len(sus)} parameter(s)", "severity": "HIGH", "cvss": 7.7,
            "cwe": "CWE-918",
            "evidence": f"Server fetched external URL and reflected content for params: {', '.join(p['param'] for p in sus)}",
            "remediation": "Validate URL against allow-list; block IP literals + internal ranges (127/8, 169.254/16, 10/8, 172.16/12, 192.168/16, ::1, fc00::/7)."}


FINDING_RULES = [_r_ssrf]
INTEL_FIELDS = [("Parameters probed", "probed_params"), ("Suspect params", "ssrf_suspects")]


@router.post("/api/vuln/a10_ssrf")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="a10_ssrf",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
