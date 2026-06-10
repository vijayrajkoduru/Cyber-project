"""Web Cache Poisoning - cache-key + header reflection check. VL-METHOD Wave 3.

Refactored 2026-06-09 to MethodologyScanner. Verify re-fires with a DIFFERENT
canary value so static-content reflection (page that happens to contain
'vlcache9k') doesn't trip the detector — only true header reflection echoes
both canaries.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import probe_url_async, http_get_h_async, http_get_async
from tools._vl_core.verify import vl_verify

router = APIRouter()

CANARY_QUICK    = "vlcache9k.example.com"
CANARY_VERIFY   = "vlcacheverify7.example.com"
TEST_HEADERS_QUICK = [
    ("X-Forwarded-Host", CANARY_QUICK),
    ("X-Forwarded-Proto", "javascript"),
]
TEST_HEADERS_DEEP = [
    ("X-Host", CANARY_QUICK),
    ("X-Original-URL", f"/?{CANARY_QUICK}"),
    ("X-Rewrite-URL", f"/?{CANARY_QUICK}"),
]


async def _fire_one(base_url, header_name, header_value, canary):
    r = await http_get_h_async(base_url, headers={header_name: header_value},
                                 timeout=8)
    if not r:
        return None
    body = r.get("body", "")
    cache_ctrl = (r.get("headers") or {}).get("cache-control", "") or ""
    if canary in body or "javascript" in body.lower():
        if "no-store" not in cache_ctrl.lower() and "private" not in cache_ctrl.lower():
            return {"header": header_name, "value": header_value, "cache": cache_ctrl[:60]}
    return None


async def _fire(base_url, headers, canary):
    hits = []
    for hn, hv in headers:
        hit = await _fire_one(base_url, hn, hv, canary)
        if hit:
            hits.append(hit)
    return hits


class WebCachePoisoning(MethodologyScanner):
    name = "web_cache_poisoning"

    async def pre_flight(self, ctx):
        base_url, base = await probe_url_async(str(ctx.host), "/")
        if not base:
            ctx.state["tested"] = 0
            ctx.state["skipped_reason"] = "Target unreachable"
            return False
        ctx.source("http")
        ctx.state["tested"] = 1
        ctx.state["base_url"] = base_url
        return True

    async def fingerprint(self, ctx):
        r = await http_get_async(ctx.state["base_url"], timeout=6)
        if r:
            hdrs = r.get("headers") or {}
            ctx.state["fingerprint"] = {
                "server": (hdrs.get("server") or "")[:80],
                "cache_control": (hdrs.get("cache-control") or "")[:80],
            }

    async def quick_probe(self, ctx):
        hits = await _fire(ctx.state["base_url"], TEST_HEADERS_QUICK, CANARY_QUICK)
        ctx.state["quick_hits"] = hits
        return [dict(h) for h in hits]

    async def deep_scan(self, ctx):
        hits = await _fire(ctx.state["base_url"], TEST_HEADERS_DEEP, CANARY_QUICK)
        ctx.state["deep_hits"] = hits
        return [dict(h) for h in hits]

    async def verify(self, ctx, finding):
        # Re-fire same header but with the VERIFY canary. Real header
        # reflection echoes both canaries; static page echoing the first
        # one wouldn't echo the second.
        header_name = finding["header"]
        # Verify value: if original was a host-like canary, swap to verify host
        # If original was the javascript scheme, that test is static (no canary)
        if "javascript" in finding["value"]:
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "javascript-scheme-static-finding"
            return finding
        # Swap the canary in the original value
        header_value = finding["value"].replace(CANARY_QUICK, CANARY_VERIFY)
        hit = await _fire_one(ctx.state["base_url"], header_name, header_value,
                                CANARY_VERIFY)
        if hit:
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = f"alt-canary-{CANARY_VERIFY}-also-echoed"
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "alt-canary-not-echoed"
        return finding


def _r_cache(s):
    verified = s.get("methodology_findings") or []
    if not verified:
        return None
    confirmed = [f for f in verified if f.get("confidence") == "CONFIRMED"]
    if confirmed:
        return {"name": f"Cacheable response reflects {len(confirmed)} unkeyed header(s) "
                         f"(CONFIRMED)",
                "severity": "MEDIUM", "cvss": 5.4, "cwe": "CWE-444",
                "evidence": "; ".join(f"{h['header']}: {h['value']}" for h in confirmed),
                "remediation": "Add these headers to Vary or remove them from response "
                                "builder. Use 'no-store' for personalised responses."}
    return {"name": f"Possible cache-poisoning surface in {len(verified)} header(s) "
                     f"(SUSPECTED)",
            "severity": "LOW", "cvss": 3.1, "cwe": "CWE-444",
            "evidence": "; ".join(f"{h['header']}: {h['value']}" for h in verified),
            "remediation": "Manually re-test with custom header values."}


FINDING_RULES = [_r_cache]
INTEL_FIELDS = [
    ("Quick-probe hits", "quick_hits"),
    ("Deep-scan hits", "deep_hits"),
    ("Verified findings", "methodology_findings"),
    ("Stage timings (ms)", "stage_timings"),
]


@router.post("/api/vuln/web_cache_poisoning")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = WebCachePoisoning()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
