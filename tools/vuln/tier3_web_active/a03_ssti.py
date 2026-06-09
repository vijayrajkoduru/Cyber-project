"""A03 SSTI - server-side template injection. VL-METHOD Wave 2.

Refactored 2026-06-09 to MethodologyScanner. Verify uses a SECOND math
expression {{8*8}}=64 — real template engine evaluates both; static page
with hardcoded 49 wouldn't change to 64.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import probe_url_async, http_get_async

router = APIRouter()

PAYLOADS_QUICK   = ["{{7*7}}"]                                  # Jinja2/Twig
PAYLOADS_DEEP    = ["${7*7}", "<%=7*7%>", "#{7*7}"]            # Velocity/JSP/Ruby
PAYLOAD_VERIFY   = "{{8*8}}"
MARKER_QUICK     = "49"
MARKER_VERIFY    = "64"
PROBE_PARAMS_QUICK = ["q", "name", "msg"]
PROBE_PARAMS_DEEP  = ["comment", "search", "template", "view"]


async def _fire(base_url, params, payloads, marker):
    hits = []
    for p in params:
        for payload in payloads:
            url = f"{base_url}?{p}={payload}"
            r = await http_get_async(url, timeout=8)
            if not r:
                continue
            body = r.get("body", "")
            # Marker must appear AND raw expression must NOT (template was evaluated)
            if marker in body and "7*7" not in body:
                hits.append({"param": p, "payload": payload})
                break
    return hits


class A03Ssti(MethodologyScanner):
    name = "a03_ssti"

    async def pre_flight(self, ctx):
        base_url, base = await probe_url_async(str(ctx.host), "/")
        if not base or base.get("status", 0) >= 500:
            ctx.state["tested"] = 0
            ctx.state["skipped_reason"] = "Target unreachable"
            return False
        ctx.source("http")
        ctx.state["tested"] = 1
        ctx.state["base_url"] = base_url
        ctx.state["probes"] = (len(PROBE_PARAMS_QUICK) + len(PROBE_PARAMS_DEEP)) * \
                               (len(PAYLOADS_QUICK) + len(PAYLOADS_DEEP))
        return True

    async def fingerprint(self, ctx):
        r = await http_get_async(ctx.state["base_url"], timeout=6)
        if r:
            hdrs = r.get("headers") or {}
            ctx.state["fingerprint"] = {
                "server":       (hdrs.get("server") or "")[:80],
                "x_powered_by": (hdrs.get("x-powered-by") or "")[:80],
            }

    async def quick_probe(self, ctx):
        hits = await _fire(ctx.state["base_url"], PROBE_PARAMS_QUICK,
                            PAYLOADS_QUICK, MARKER_QUICK)
        ctx.state["quick_hits"] = hits
        return [dict(h) for h in hits]

    async def deep_scan(self, ctx):
        hits = await _fire(ctx.state["base_url"], PROBE_PARAMS_DEEP,
                            PAYLOADS_QUICK + PAYLOADS_DEEP, MARKER_QUICK)
        ctx.state["deep_hits"] = hits
        return [dict(h) for h in hits]

    async def verify(self, ctx, finding):
        # Re-fire with {{8*8}} - real template engine returns 64; static
        # page that just has "49" stays at 49.
        url = f"{ctx.state['base_url']}?{finding['param']}={PAYLOAD_VERIFY}"
        r = await http_get_async(url, timeout=8)
        if not r:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "verify-probe-failed"
            return finding
        body = r.get("body", "")
        if MARKER_VERIFY in body and "8*8" not in body:
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = f"alt-math-{PAYLOAD_VERIFY}-evaluated"
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "alt-math-not-evaluated"
        return finding


def _r_ssti(s):
    verified = s.get("methodology_findings") or []
    if not verified:
        return None
    confirmed = [f for f in verified if f.get("confidence") == "CONFIRMED"]
    if confirmed:
        params = ", ".join(f["param"] for f in confirmed)
        return {"name": f"Server-side template evaluation CONFIRMED in {len(confirmed)} parameter(s)",
                "severity": "CRITICAL", "cvss": 9.0, "cwe": "CWE-1336",
                "evidence": f"Both 7*7 -> 49 AND 8*8 -> 64 evaluated by template engine via: {params}",
                "remediation": "Never render user input as template source. Use a sandboxed renderer "
                                "with no eval-capable filters."}
    params = ", ".join(f["param"] for f in verified)
    return {"name": f"Template engine evaluation possible in {len(verified)} parameter(s) (SUSPECTED)",
            "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-1336",
            "evidence": f"49 appeared but 8*8 didn't evaluate to 64. Possible static page. Params: {params}",
            "remediation": "Manually verify each parameter with custom math expression."}


FINDING_RULES = [_r_ssti]
INTEL_FIELDS = [
    ("Probes sent", "probes"),
    ("Quick-probe hits", "quick_hits"),
    ("Deep-scan hits", "deep_hits"),
    ("Verified findings", "methodology_findings"),
    ("Stage timings (ms)", "stage_timings"),
]


@router.post("/api/vuln/a03_ssti")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = A03Ssti()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
