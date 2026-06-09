"""A03 XSS - passive reflection check. VL-METHOD Wave 1.

Refactored 2026-06-09 to MethodologyScanner. Same payload-firing pattern as
a03_sql_injection: pre_flight -> fingerprint -> quick_probe (3 params) ->
deep_scan (5 params if quick hit) -> verify (re-fire alt canary).

Strategy: inject a benign canary string (no <script>, no payload). Flag if
the canary appears unescaped in HTML body. Verify re-fires with a DIFFERENT
canary to confirm the response is dynamically reflecting input rather than
echoing a static page that happens to contain "vlxss9k4q".
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import probe_url_async, http_get_async

router = APIRouter()

CANARY        = "vlxss9k4q"
CANARY_VERIFY = "vlxss7m2p"     # different shape, same length class
PROBE_PARAMS_QUICK = ["q", "search", "name"]
PROBE_PARAMS_DEEP  = ["msg", "comment", "ref", "callback", "v"]


async def _fire(base_url, params, canary):
    reflected = []
    for p in params:
        url = f"{base_url}?{p}={canary}"
        r = await http_get_async(url, timeout=8)
        if not r:
            continue
        body = r.get("body", "")
        if canary in body:
            ctype = (r.get("headers") or {}).get("content-type", "")
            if "html" in ctype.lower() or "<" in body[:200]:
                reflected.append({"param": p, "status": r.get("status"),
                                  "canary": canary})
    return reflected


class A03Xss(MethodologyScanner):
    name = "a03_xss"

    async def pre_flight(self, ctx):
        base_url, base = await probe_url_async(str(ctx.host), "/")
        if not base or base.get("status", 0) >= 500:
            ctx.state["tested"] = 0
            ctx.state["skipped_reason"] = "Target unreachable"
            return False
        ctx.source("http")
        ctx.state["tested"] = 1
        ctx.state["base_url"] = base_url
        ctx.state["probed_params"] = len(PROBE_PARAMS_QUICK) + len(PROBE_PARAMS_DEEP)
        return True

    async def fingerprint(self, ctx):
        # Light fingerprint - capture Content-Type / Server for the home page
        r = await http_get_async(ctx.state["base_url"], timeout=6)
        if r:
            hdrs = r.get("headers") or {}
            ctx.state["fingerprint"] = {
                "server":       (hdrs.get("server") or "")[:80],
                "content_type": (hdrs.get("content-type") or "")[:80],
            }

    async def quick_probe(self, ctx):
        hits = await _fire(ctx.state["base_url"], PROBE_PARAMS_QUICK, CANARY)
        ctx.state["quick_hits"] = hits
        return [{"param": h["param"], "status": h["status"]} for h in hits]

    async def deep_scan(self, ctx):
        hits = await _fire(ctx.state["base_url"], PROBE_PARAMS_DEEP, CANARY)
        ctx.state["deep_hits"] = hits
        return [{"param": h["param"], "status": h["status"]} for h in hits]

    async def verify(self, ctx, finding):
        # Re-fire with a DIFFERENT canary. Real reflection echoes both;
        # static page or canary-leak echoes only the first.
        url = f"{ctx.state['base_url']}?{finding['param']}={CANARY_VERIFY}"
        r = await http_get_async(url, timeout=8)
        if not r or CANARY_VERIFY not in (r.get("body") or ""):
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "alt-canary-not-reflected"
            return finding
        finding["confidence"] = "CONFIRMED"
        finding["verification_method"] = f"alt-canary-{CANARY_VERIFY}"
        return finding


def _r_xss(s):
    verified = s.get("methodology_findings") or []
    if not verified:
        return None
    confirmed = [f for f in verified if f.get("confidence") == "CONFIRMED"]
    if confirmed:
        params = ", ".join(f["param"] for f in confirmed)
        return {"name": f"User input reflected unescaped in {len(confirmed)} parameter(s) (CONFIRMED)",
                "severity": "MEDIUM", "cvss": 6.1, "cwe": "CWE-79",
                "evidence": f"Two distinct canaries both echoed in HTML body via: {params}",
                "remediation": "Apply context-aware HTML entity encoding on output. "
                                "Use a Content Security Policy."}
    params = ", ".join(f["param"] for f in verified)
    return {"name": f"User input may be reflected in {len(verified)} parameter(s) (SUSPECTED)",
            "severity": "LOW", "cvss": 3.1, "cwe": "CWE-79",
            "evidence": f"First canary echoed but verify canary did not reproduce. "
                         f"Possible static page or canary leak. Params: {params}",
            "remediation": "Manually verify each parameter before remediation."}


FINDING_RULES = [_r_xss]
INTEL_FIELDS = [
    ("Parameters probed", "probed_params"),
    ("Quick-probe hits", "quick_hits"),
    ("Deep-scan hits",   "deep_hits"),
    ("Verified findings", "methodology_findings"),
    ("Stage timings (ms)", "stage_timings"),
]


@router.post("/api/vuln/a03_xss")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = A03Xss()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
