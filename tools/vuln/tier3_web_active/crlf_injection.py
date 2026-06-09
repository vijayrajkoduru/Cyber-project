"""CRLF Injection - passive header-injection detection. VL-METHOD Wave 2.

Refactored 2026-06-09 to MethodologyScanner. Verify re-fires with a DIFFERENT
injected header name to confirm dynamic header reflection rather than a
pre-existing header that happens to contain the original marker.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import probe_url_async, http_get_async

router = APIRouter()

INJECT_QUICK   = "test%0d%0aSet-Cookie:%20vlcrlf=1"
INJECT_VERIFY  = "test%0d%0aX-Vlcheck:%20vlrechk"
MARKER_QUICK   = "vlcrlf"
MARKER_VERIFY  = "vlrechk"
PROBE_PARAMS_QUICK = ["url", "redirect", "next"]
PROBE_PARAMS_DEEP  = ["q", "page", "lang"]


async def _fire(base_url, params, payload, marker):
    hits = []
    for p in params:
        url = f"{base_url}?{p}={payload}"
        r = await http_get_async(url, timeout=8)
        if not r:
            continue
        for hn, hv in (r.get("headers") or {}).items():
            if marker in str(hv).lower():
                hits.append({"param": p, "header": hn, "value": str(hv)[:80]})
                break
    return hits


class CrlfInjection(MethodologyScanner):
    name = "crlf_injection"

    async def pre_flight(self, ctx):
        base_url, base = await probe_url_async(str(ctx.host), "/")
        if not base:
            ctx.state["tested"] = 0
            ctx.state["skipped_reason"] = "Target unreachable"
            return False
        ctx.source("http")
        ctx.state["tested"] = 1
        ctx.state["base_url"] = base_url
        ctx.state["probed_params"] = len(PROBE_PARAMS_QUICK) + len(PROBE_PARAMS_DEEP)
        return True

    async def fingerprint(self, ctx):
        r = await http_get_async(ctx.state["base_url"], timeout=6)
        if r:
            hdrs = r.get("headers") or {}
            ctx.state["fingerprint"] = {
                "server": (hdrs.get("server") or "")[:80],
            }

    async def quick_probe(self, ctx):
        hits = await _fire(ctx.state["base_url"], PROBE_PARAMS_QUICK,
                            INJECT_QUICK, MARKER_QUICK)
        ctx.state["quick_hits"] = hits
        return [dict(h) for h in hits]

    async def deep_scan(self, ctx):
        hits = await _fire(ctx.state["base_url"], PROBE_PARAMS_DEEP,
                            INJECT_QUICK, MARKER_QUICK)
        ctx.state["deep_hits"] = hits
        return [dict(h) for h in hits]

    async def verify(self, ctx, finding):
        url = f"{ctx.state['base_url']}?{finding['param']}={INJECT_VERIFY}"
        r = await http_get_async(url, timeout=8)
        if not r:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "verify-probe-failed"
            return finding
        for hn, hv in (r.get("headers") or {}).items():
            if MARKER_VERIFY in str(hv).lower():
                finding["confidence"] = "CONFIRMED"
                finding["verification_method"] = f"alt-header-{MARKER_VERIFY}-injected"
                return finding
        finding["confidence"] = "SUSPECTED"
        finding["verification_method"] = "alt-header-not-injected"
        return finding


def _r_crlf(s):
    verified = s.get("methodology_findings") or []
    if not verified:
        return None
    confirmed = [f for f in verified if f.get("confidence") == "CONFIRMED"]
    if confirmed:
        return {"name": f"CRLF / header injection CONFIRMED in {len(confirmed)} parameter(s)",
                "severity": "HIGH", "cvss": 7.4, "cwe": "CWE-93",
                "evidence": "; ".join(f"{f['param']} -> {f['header']}" for f in confirmed),
                "remediation": "Reject CR (\\r 0x0d) and LF (\\n 0x0a) in any value that "
                                "builds HTTP response headers."}
    return {"name": f"CRLF marker found in headers via {len(verified)} parameter(s) (SUSPECTED)",
            "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-93",
            "evidence": "; ".join(f"{f['param']} -> {f['header']}" for f in verified) +
                         " - second header probe did not reproduce",
            "remediation": "Manually re-test with custom header names."}


FINDING_RULES = [_r_crlf]
INTEL_FIELDS = [
    ("Parameters probed", "probed_params"),
    ("Quick-probe hits", "quick_hits"),
    ("Deep-scan hits", "deep_hits"),
    ("Verified findings", "methodology_findings"),
    ("Stage timings (ms)", "stage_timings"),
]


@router.post("/api/vuln/crlf_injection")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = CrlfInjection()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
