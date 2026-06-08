"""A03 SQL Injection - passive error-based detection. Self-contained, no cross-module routing.
Strategy: probe target with safe single-quote payload in common param names, look for SQL error
fingerprints in response body. Zero exploitation, evidence-only."""
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url_async, http_get_async, SQL_ERROR_PATTERNS

router = APIRouter()

PROBE_PARAMS = ["id", "q", "search", "page", "user", "uid", "item", "category"]
PAYLOAD = "1'\""


async def gather(ctx):
    host = str(ctx.host)
    base_url, base = await probe_url_async(host, "/")
    if not base or base.get("status", 0) >= 500:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable on HTTP/HTTPS"
        return
    ctx.source(f"http-{base.get('status')}")
    ctx.state["tested"] = 1
    ctx.state["probed_params"] = len(PROBE_PARAMS)
    hits = []
    for p in PROBE_PARAMS:
        url = f"{base_url}?{p}={PAYLOAD}"
        r = await http_get_async(url, timeout=8)
        if not r:
            continue
        body_lower = r.get("body", "").lower()
        for pattern in SQL_ERROR_PATTERNS:
            if re.search(pattern, body_lower):
                hits.append({"param": p, "pattern": pattern, "status": r.get("status")})
                break
    ctx.state["sql_error_hits"] = hits


def _r_sqli(s):
    hits = s.get("sql_error_hits") or []
    if not hits:
        return None
    return {"name": f"SQL error message exposed via {len(hits)} parameter(s)", "severity": "HIGH", "cvss": 7.5,
            "cwe": "CWE-89",
            "evidence": f"Single-quote payload triggered SQL error in: {', '.join(h['param'] for h in hits)}",
            "remediation": "Use parameterised queries / prepared statements. Suppress detailed DB errors in production responses."}


FINDING_RULES = [_r_sqli]
INTEL_FIELDS = [("Parameters probed", "probed_params"), ("Error hits", "sql_error_hits")]


@router.post("/api/vuln/a03_sql_injection")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="a03_sql_injection",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
