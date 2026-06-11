"""Open Redirect - passive Location-header redirect check. VL-METHOD Wave 2.

Refactored 2026-06-09 to MethodologyScanner. Verify re-fires with a SECOND
external host (example.com instead of example.org) so we confirm dynamic
URL-input handling rather than a hardcoded redirect to example.org.
"""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import probe_url_async, http_get_async
from tools._vl_core.verify import vl_verify

router = APIRouter()

REDIRECT_QUICK   = "https://example.org/"
REDIRECT_VERIFY  = "https://example.com/"
HOST_QUICK       = "example.org"
HOST_VERIFY      = "example.com"
PROBE_PARAMS_QUICK = ["url", "redirect", "redirect_uri", "next", "return"]
PROBE_PARAMS_DEEP  = ["returnTo", "continue", "goto", "destination",
                      "out", "to", "target"]


async def _fire(base_url, params, payload, host):
    async def _probe(p):
        url = f"{base_url}?{p}={payload}"
        r = await http_get_async(url, timeout=8)
        if not r:
            return None
        loc = (r.get("headers") or {}).get("location", "") or ""
        if host in loc.lower():
            return {"param": p, "location": loc[:120],
                    "status": r.get("status")}
        return None

    results = await asyncio.gather(
        *[_probe(p) for p in params],
        return_exceptions=True)
    hits = []
    for res in results:
        if isinstance(res, BaseException) or res is None:
            continue
        hits.append(res)
    return hits


class OpenRedirectCheck(MethodologyScanner):
    name = "open_redirect_check"

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
                            REDIRECT_QUICK, HOST_QUICK)
        ctx.state["quick_hits"] = hits
        return [dict(h) for h in hits]

    async def deep_scan(self, ctx):
        hits = await _fire(ctx.state["base_url"], PROBE_PARAMS_DEEP,
                            REDIRECT_QUICK, HOST_QUICK)
        ctx.state["deep_hits"] = hits
        return [dict(h) for h in hits]

    async def verify(self, ctx, finding):
        url = f"{ctx.state['base_url']}?{finding['param']}={REDIRECT_VERIFY}"
        r = await http_get_async(url, timeout=8)
        if not r:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "verify-probe-failed"
            return finding
        loc = (r.get("headers") or {}).get("location", "") or ""
        if HOST_VERIFY in loc.lower():
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = f"alt-host-{HOST_VERIFY}-redirected"
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "alt-host-not-redirected"
        return finding


def _r_redir(s):
    verified = s.get("methodology_findings") or []
    if not verified:
        return None
    confirmed = [f for f in verified if f.get("confidence") == "CONFIRMED"]
    if confirmed:
        return {"name": f"Open redirect CONFIRMED in {len(confirmed)} parameter(s)",
                "severity": "MEDIUM", "cvss": 6.1, "cwe": "CWE-601",
                "evidence": "Both example.org and example.com followed via: " +
                             ", ".join(f["param"] for f in confirmed),
                "remediation": "Validate redirect target against an allow-list. Reject "
                                "schemes != https + hosts not in your domain."}
    return {"name": f"Possible open redirect in {len(verified)} parameter(s) (SUSPECTED)",
            "severity": "LOW", "cvss": 3.1, "cwe": "CWE-601",
            "evidence": "Initial redirect followed but alt host did not. Possible "
                         "hardcoded redirect. Params: " +
                         ", ".join(f["param"] for f in verified),
            "remediation": "Manually verify each parameter with custom URLs."}


FINDING_RULES = [_r_redir]
INTEL_FIELDS = [
    ("Parameters probed", "probed_params"),
    ("Quick-probe hits", "quick_hits"),
    ("Deep-scan hits", "deep_hits"),
    ("Verified findings", "methodology_findings"),
    ("Stage timings (ms)", "stage_timings"),
]


@router.post("/api/vuln/open_redirect_check")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = OpenRedirectCheck()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
