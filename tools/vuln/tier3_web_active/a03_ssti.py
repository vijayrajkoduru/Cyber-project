"""A03 Template Injection (SSTI) - passive math-eval detection. Self-contained.
Strategy: send {{7*7}} and ${7*7} payloads, look for '49' in unexpected position."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url, http_get

router = APIRouter()

PAYLOADS = ["{{7*7}}", "${7*7}", "<%=7*7%>", "#{7*7}"]
MARKER = "49"
PROBE_PARAMS = ["q", "name", "msg", "comment", "search", "template", "view"]


async def gather(ctx):
    host = str(ctx.host)
    base_url, base = probe_url(host, "/")
    if not base or base.get("status", 0) >= 500:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    ctx.state["probes"] = len(PROBE_PARAMS) * len(PAYLOADS)
    hits = []
    for p in PROBE_PARAMS:
        for payload in PAYLOADS:
            url = f"{base_url}?{p}={payload}"
            r = http_get(url, timeout=8)
            if not r:
                continue
            body = r.get("body", "")
            # Sanity: 49 must appear AND the raw payload chars must NOT (template was evaluated)
            if MARKER in body and "7*7" not in body:
                hits.append({"param": p, "payload": payload})
                break
    ctx.state["ssti_hits"] = hits


def _r_ssti(s):
    hits = s.get("ssti_hits") or []
    if not hits:
        return None
    return {"name": f"Server-side template evaluation observed in {len(hits)} parameter(s)", "severity": "CRITICAL", "cvss": 9.0,
            "cwe": "CWE-1336",
            "evidence": f"Math expression evaluated by template engine in: {', '.join(h['param'] for h in hits)}",
            "remediation": "Never render user input as template source. Use a sandboxed renderer with no eval-capable filters."}


FINDING_RULES = [_r_ssti]
INTEL_FIELDS = [("Probes sent", "probes"), ("SSTI hits", "ssti_hits")]


@router.post("/api/vuln/a03_ssti")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="a03_ssti",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
