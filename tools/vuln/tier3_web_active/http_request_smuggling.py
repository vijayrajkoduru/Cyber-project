"""HTTP Request Smuggling - passive header-discrepancy hint. Self-contained.
Strategy: probe target, check if Connection/Keep-Alive/Transfer-Encoding combinations
+ ambiguous header handling produce smuggling-prone signatures. CONSERVATIVE: only
flags strong indicators (chunked + content-length both echoed, weird HTTP server)."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url, http_get_h

router = APIRouter()


async def gather(ctx):
    host = str(ctx.host)
    base_url, base = probe_url(host, "/")
    if not base:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    headers = base.get("headers", {}) or {}
    server = (headers.get("server") or "").lower()
    via = headers.get("via") or ""
    has_te = "transfer-encoding" in headers
    has_cl = "content-length" in headers
    indicators = []
    # CDN/proxy + origin combo is a classic smuggling surface
    if via:
        indicators.append(f"Via header present (proxy chain): {via}")
    if "cloudflare" in server or "akamai" in server or "fastly" in server:
        indicators.append(f"CDN edge: {server.split()[0]}")
    if has_te and has_cl:
        indicators.append("Both Transfer-Encoding and Content-Length present in response (RFC 7230 ambiguity)")
    # Send TE: chunked with body to see how server handles it
    r2 = http_get_h(base_url, headers={"Transfer-Encoding": "chunked", "Connection": "keep-alive"}, timeout=6)
    if r2 and r2.get("status") not in (200, 204, 301, 302, 304, 400):
        indicators.append(f"Server returned status {r2.get('status')} on chunked GET (unusual)")
    ctx.state["smuggling_indicators"] = indicators
    ctx.state["server_header"] = server[:80]


def _r_smug(s):
    ind = s.get("smuggling_indicators") or []
    # Require >=2 indicators to flag (zero-FP discipline)
    if len(ind) < 2:
        return None
    return {"name": "HTTP request smuggling surface present (proxy + ambiguous headers)",
            "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-444",
            "evidence": "; ".join(ind),
            "remediation": "Disable HTTP/1.1 keep-alive between proxy and origin OR use HTTP/2 end-to-end. Reject requests with both TE and CL."}


FINDING_RULES = [_r_smug]
INTEL_FIELDS = [("Server", "server_header"), ("Smuggling indicators", "smuggling_indicators")]


@router.post("/api/vuln/http_request_smuggling")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="http_request_smuggling",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
