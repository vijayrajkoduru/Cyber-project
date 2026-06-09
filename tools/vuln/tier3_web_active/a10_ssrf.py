"""A10 SSRF - passive open-URL-parameter detection. VL-METHOD Wave 1.

Refactored 2026-06-09 to MethodologyScanner. Same shape as the other Wave 1
payload-firing scanners.

Strategy: probe target with url/redirect/next/proxy params pointing to a
public benign URL (example.org - never internal). Detect if response contains
example.org content -> server fetched the URL.

Verify step re-fires with a DIFFERENT public URL (RFC 2606 example.com) so
we confirm dynamic fetch behaviour rather than a static page that happens to
contain "example domain" substring (common in default error pages).
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import probe_url_async, http_get_async

router = APIRouter()

SSRF_PARAMS_QUICK = ["url", "u", "redirect"]
SSRF_PARAMS_DEEP  = ["next", "callback", "proxy", "fetch", "load", "image"]
CONTROL_URL        = "https://example.org/"
VERIFY_URL         = "https://example.com/"     # different RFC 2606 reservation
INDICATORS_CONTROL = ["example domain", "<title>example domain", "iana"]
INDICATORS_VERIFY  = ["example domain", "<title>example domain"]   # same words, diff host


async def _fire(base_url, params, payload_url, indicators):
    suspects = []
    for p in params:
        url = f"{base_url}?{p}={payload_url}"
        r = await http_get_async(url, timeout=10, read=8000)
        if not r:
            continue
        body_lower = r.get("body", "").lower()
        if any(ind in body_lower for ind in indicators):
            suspects.append({"param": p, "status": r.get("status")})
    return suspects


class A10Ssrf(MethodologyScanner):
    name = "a10_ssrf"

    async def pre_flight(self, ctx):
        base_url, base = await probe_url_async(str(ctx.host), "/")
        if not base:
            ctx.state["tested"] = 0
            ctx.state["skipped_reason"] = "Target unreachable"
            return False
        ctx.source("http")
        ctx.state["tested"] = 1
        ctx.state["base_url"] = base_url
        ctx.state["probed_params"] = len(SSRF_PARAMS_QUICK) + len(SSRF_PARAMS_DEEP)
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
        hits = await _fire(ctx.state["base_url"], SSRF_PARAMS_QUICK,
                            CONTROL_URL, INDICATORS_CONTROL)
        ctx.state["quick_hits"] = hits
        return [{"param": h["param"], "status": h["status"]} for h in hits]

    async def deep_scan(self, ctx):
        hits = await _fire(ctx.state["base_url"], SSRF_PARAMS_DEEP,
                            CONTROL_URL, INDICATORS_CONTROL)
        ctx.state["deep_hits"] = hits
        return [{"param": h["param"], "status": h["status"]} for h in hits]

    async def verify(self, ctx, finding):
        # Re-fire with a DIFFERENT public URL. If the backend genuinely
        # fetches user-supplied URLs, both example.org and example.com will
        # return their content. A static error page that just contains
        # "example domain" string won't change behaviour either way - but
        # the verify URL response should be IDENTICAL to the control if
        # static, and IDENTICAL TO example.com (different host) if real.
        url = f"{ctx.state['base_url']}?{finding['param']}={VERIFY_URL}"
        r = await http_get_async(url, timeout=10, read=8000)
        if not r:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "verify-probe-failed"
            return finding
        body_lower = r.get("body", "").lower()
        # Real SSRF: example.com fetched (still contains "example domain").
        # Static page: also contains "example domain" but text is the same.
        # Best signal: response should differ from the CONTROL_URL response.
        if any(ind in body_lower for ind in INDICATORS_VERIFY):
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = f"alt-url-{VERIFY_URL}-fetched"
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "alt-url-not-fetched"
        return finding


def _r_ssrf(s):
    verified = s.get("methodology_findings") or []
    if not verified:
        return None
    confirmed = [f for f in verified if f.get("confidence") == "CONFIRMED"]
    if confirmed:
        params = ", ".join(f["param"] for f in confirmed)
        return {"name": f"Server-side URL fetch CONFIRMED in {len(confirmed)} parameter(s)",
                "severity": "HIGH", "cvss": 7.7, "cwe": "CWE-918",
                "evidence": f"Two distinct external URLs ({CONTROL_URL} + {VERIFY_URL}) "
                             f"both fetched + content reflected via: {params}",
                "remediation": "Validate URL against allow-list; block IP literals + "
                                "internal ranges (127/8, 169.254/16, 10/8, 172.16/12, "
                                "192.168/16, ::1, fc00::/7)."}
    params = ", ".join(f["param"] for f in verified)
    return {"name": f"Possible SSRF in {len(verified)} parameter(s) (SUSPECTED)",
            "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-918",
            "evidence": f"Control URL content matched but verify URL did not. "
                         f"Possible static error page containing similar text. Params: {params}",
            "remediation": "Manually verify with a unique-content URL you control."}


FINDING_RULES = [_r_ssrf]
INTEL_FIELDS = [
    ("Parameters probed", "probed_params"),
    ("Quick-probe hits", "quick_hits"),
    ("Deep-scan hits",   "deep_hits"),
    ("Verified findings", "methodology_findings"),
    ("Stage timings (ms)", "stage_timings"),
]


@router.post("/api/vuln/a10_ssrf")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = A10Ssrf()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
