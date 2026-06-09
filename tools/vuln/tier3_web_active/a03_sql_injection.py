"""A03 SQL Injection - passive error-based detection. VL-METHOD Wave 1.

Refactored 2026-06-09 from 1-shot gather() to 6-stage MethodologyScanner.
The 6 useful stages (chain_handoff omitted per no-chained-exploitation rule):

  pre_flight    : target HTTP-reachable + not 5xx
  fingerprint   : detect DB backend hints (Server header, X-Powered-By)
  quick_probe   : fire payload on FIRST 3 high-value params (cheap triage)
  deep_scan     : if quick had hits, fire on remaining 5 params + alt payload
  verify        : re-fire winning hit with different payload to confirm not
                  static page / WAF echo / cached error
  privilege_check: N/A for SQL-error fingerprints (no creds returned)

Strategy still zero-exploitation: probe with safe single-quote payload in common
param names, match SQL error fingerprints in response body. Evidence-only.
"""
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import probe_url_async, http_get_async, SQL_ERROR_PATTERNS

router = APIRouter()

PROBE_PARAMS_QUICK = ["id", "q", "search"]                  # high-value triage
PROBE_PARAMS_DEEP  = ["page", "user", "uid", "item", "category"]
PAYLOAD            = "1'\""                                   # safe single-quote+double-quote
PAYLOAD_VERIFY     = "1)'"                                    # alt shape for verify step


async def _fire(base_url, params, payload):
    """Fire `payload` against each param, return list of error-matched hits."""
    hits = []
    for p in params:
        url = f"{base_url}?{p}={payload}"
        r = await http_get_async(url, timeout=8)
        if not r:
            continue
        body_lower = r.get("body", "").lower()
        for pattern in SQL_ERROR_PATTERNS:
            if re.search(pattern, body_lower):
                hits.append({"param": p, "pattern": pattern,
                             "status": r.get("status"), "payload": payload})
                break
    return hits


class A03SqlInjection(MethodologyScanner):
    name = "a03_sql_injection"

    async def pre_flight(self, ctx):
        base_url, base = await probe_url_async(str(ctx.host), "/")
        if not base or base.get("status", 0) >= 500:
            ctx.state["tested"] = 0
            ctx.state["skipped_reason"] = "Target unreachable on HTTP/HTTPS"
            return False
        ctx.source(f"http-{base.get('status')}")
        ctx.state["tested"] = 1
        ctx.state["base_url"] = base_url
        ctx.state["base_status"] = base.get("status")
        ctx.state["probed_params"] = len(PROBE_PARAMS_QUICK) + len(PROBE_PARAMS_DEEP)
        return True

    async def fingerprint(self, ctx):
        # Cheap fingerprint: server / x-powered-by headers hint at backend DB
        r = await http_get_async(ctx.state["base_url"], timeout=6)
        if r:
            hdrs = r.get("headers") or {}
            ctx.state["fingerprint"] = {
                "server":       (hdrs.get("server") or "")[:80],
                "x_powered_by": (hdrs.get("x-powered-by") or "")[:80],
            }

    async def quick_probe(self, ctx):
        hits = await _fire(ctx.state["base_url"], PROBE_PARAMS_QUICK, PAYLOAD)
        ctx.state["quick_hits"] = hits
        # Return as preliminary findings (one per hit) so MethodologyScanner
        # routes them through verify+privilege_check stages.
        return [{"param": h["param"], "pattern": h["pattern"],
                 "status": h["status"], "payload": h["payload"]} for h in hits]

    async def deep_scan(self, ctx):
        # Only runs when quick_probe found something (gated by base class) OR
        # options.always_deep=True. So a clean quick_probe skips this entirely.
        hits = await _fire(ctx.state["base_url"], PROBE_PARAMS_DEEP, PAYLOAD)
        ctx.state["deep_hits"] = hits
        return [{"param": h["param"], "pattern": h["pattern"],
                 "status": h["status"], "payload": h["payload"]} for h in hits]

    async def verify(self, ctx, finding):
        # Re-fire with a STRUCTURALLY-DIFFERENT payload. If the original was
        # a single-quote injection, try a closing-paren injection — same
        # backend should still error, but a static error page or WAF echo
        # will NOT (different input shape, different response).
        url = f"{ctx.state['base_url']}?{finding['param']}={PAYLOAD_VERIFY}"
        r = await http_get_async(url, timeout=8)
        if not r:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "verify-probe-failed"
            return finding
        body_lower = r.get("body", "").lower()
        confirmed = any(re.search(pat, body_lower) for pat in SQL_ERROR_PATTERNS)
        finding["confidence"] = "CONFIRMED" if confirmed else "SUSPECTED"
        finding["verification_method"] = f"alt-payload-{PAYLOAD_VERIFY}"
        return finding


def _r_sqli(s):
    # MethodologyScanner stamps verified findings on state["methodology_findings"].
    # Roll up by confidence so the report shows CONFIRMED vs SUSPECTED counts.
    verified = s.get("methodology_findings") or []
    if not verified:
        return None
    confirmed = [f for f in verified if f.get("confidence") == "CONFIRMED"]
    if confirmed:
        params = ", ".join(f["param"] for f in confirmed)
        return {"name": f"SQL error exposed via {len(confirmed)} parameter(s) (CONFIRMED)",
                "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-89",
                "evidence": f"Two distinct payloads ({PAYLOAD} + {PAYLOAD_VERIFY}) "
                             f"both triggered SQL errors via: {params}",
                "remediation": "Use parameterised queries / prepared statements. "
                                "Suppress detailed DB errors in production responses."}
    # All findings are SUSPECTED (first payload errored but verify didn't)
    params = ", ".join(f["param"] for f in verified)
    return {"name": f"SQL error pattern observed via {len(verified)} parameter(s) (SUSPECTED)",
            "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-89",
            "evidence": f"Initial payload {PAYLOAD} matched SQL error fingerprint but "
                         f"alt payload did not reproduce. Static error page or WAF "
                         f"echo possible. Params: {params}",
            "remediation": "Manually verify each param before remediation. Use "
                            "parameterised queries / prepared statements."}


FINDING_RULES = [_r_sqli]
INTEL_FIELDS = [
    ("Parameters probed", "probed_params"),
    ("Quick-probe hits", "quick_hits"),
    ("Deep-scan hits",   "deep_hits"),
    ("Verified findings", "methodology_findings"),
    ("Stage timings (ms)", "stage_timings"),
]


@router.post("/api/vuln/a03_sql_injection")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = A03SqlInjection()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
