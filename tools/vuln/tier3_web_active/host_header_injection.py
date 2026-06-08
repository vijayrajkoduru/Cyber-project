"""Host Header Injection - passive Host-header reflection check. Self-contained.
Strategy: send GET / with Host: evil.attacker.tld, check if attacker host echoes in
Location/body/Set-Cookie/Set-Cookie domain or password-reset link patterns."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url_async, http_get_h_async

router = APIRouter()

ATTACKER_HOST = "evil.vlattacker.com"


async def gather(ctx):
    host = str(ctx.host)
    base_url, base = await probe_url_async(host, "/")
    if not base:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    r = await http_get_h_async(base_url, headers={"Host": ATTACKER_HOST}, timeout=8)
    if not r:
        ctx.state["host_response"] = None
        return
    issues = []
    # Check Location header for attacker host
    loc = (r.get("headers", {}) or {}).get("location", "") or ""
    if ATTACKER_HOST in loc.lower():
        issues.append({"where": "Location header", "value": loc[:120]})
    # Check body for reflection
    body = r.get("body", "") or ""
    if ATTACKER_HOST in body.lower():
        issues.append({"where": "Response body", "value": "Attacker host reflected"})
    # Check Set-Cookie domain
    sc = (r.get("headers", {}) or {}).get("set-cookie", "") or ""
    if ATTACKER_HOST in sc.lower():
        issues.append({"where": "Set-Cookie domain", "value": sc[:120]})
    ctx.state["host_injection_issues"] = issues
    ctx.state["host_status"] = r.get("status")


def _r_hh(s):
    issues = s.get("host_injection_issues") or []
    if not issues:
        return None
    return {"name": "Host header reflected without validation", "severity": "MEDIUM", "cvss": 6.1,
            "cwe": "CWE-444",
            "evidence": "; ".join(f"{i['where']}: {i['value']}" for i in issues),
            "remediation": "Pin trusted hostnames in app + reverse proxy (server_name in nginx, Host whitelist in framework). Never use Host header to build absolute URLs."}


FINDING_RULES = [_r_hh]
INTEL_FIELDS = [("Response status", "host_status"), ("Host injection issues", "host_injection_issues")]


@router.post("/api/vuln/host_header_injection")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="host_header_injection",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
