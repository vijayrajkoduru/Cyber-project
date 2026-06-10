"""HTTP Request Smuggling - VL-METHOD Wave 4.

Refactored 2026-06-09 to MethodologyScanner. Verify refetches the base URL +
re-runs the chunked-GET probe — if the same indicators reproduce (proxy chain,
TE+CL coexistence, weird chunked status), CONFIRMED. CDN/proxy fingerprints
are static facts; chunked-GET status can flap on retry which is the FP risk.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import probe_url_async, http_get_h_async, http_get_async
from tools._vl_core.verify import vl_verify

router = APIRouter()


def _collect_indicators(base, chunk_resp):
    headers = base.get("headers", {}) or {}
    server = (headers.get("server") or "").lower()
    via = headers.get("via") or ""
    has_te = "transfer-encoding" in headers
    has_cl = "content-length" in headers
    indicators = []
    if via:
        indicators.append({"kind": "via", "evidence": f"Via header present (proxy chain): {via}"})
    if "cloudflare" in server or "akamai" in server or "fastly" in server:
        indicators.append({"kind": "cdn",
                           "evidence": f"CDN edge: {server.split()[0]}"})
    if has_te and has_cl:
        indicators.append({"kind": "te-cl",
                           "evidence": "Both Transfer-Encoding and Content-Length in response (RFC 7230 ambiguity)"})
    if chunk_resp and chunk_resp.get("status") not in (200, 204, 301, 302, 304, 400):
        indicators.append({"kind": "chunked-status",
                           "evidence": f"Server returned status {chunk_resp.get('status')} on chunked GET (unusual)"})
    return indicators, server


async def _chunked_probe(base_url):
    return await http_get_h_async(base_url,
        headers={"Transfer-Encoding": "chunked", "Connection": "keep-alive"},
        timeout=6)


class HttpRequestSmuggling(MethodologyScanner):
    name = "http_request_smuggling"

    async def pre_flight(self, ctx):
        base_url, base = await probe_url_async(str(ctx.host), "/")
        if not base:
            ctx.state["tested"] = 0
            ctx.state["skipped_reason"] = "Target unreachable"
            return False
        ctx.source("http")
        ctx.state["tested"] = 1
        ctx.state["base_url"] = base_url
        ctx.state["_base_resp"] = base
        return True

    async def fingerprint(self, ctx):
        hdrs = ctx.state["_base_resp"].get("headers") or {}
        ctx.state["fingerprint"] = {
            "server": (hdrs.get("server") or "")[:80],
            "via":    (hdrs.get("via") or "")[:80],
        }
        ctx.state["server_header"] = ctx.state["fingerprint"]["server"]

    async def quick_probe(self, ctx):
        chunk_resp = await _chunked_probe(ctx.state["base_url"])
        indicators, _ = _collect_indicators(ctx.state["_base_resp"], chunk_resp)
        ctx.state["smuggling_indicators"] = indicators
        ctx.state["quick_hits"] = indicators
        # Only emit a finding if >=2 indicators (zero-FP threshold)
        if len(indicators) < 2:
            return []
        return [{"kind": "aggregate", "indicators": [i["kind"] for i in indicators],
                 "evidence": "; ".join(i["evidence"] for i in indicators)}]

    async def deep_scan(self, ctx):
        # Single-target scanner, no further surface
        return []

    async def verify(self, ctx, finding):
        # Refetch base + chunked probe. The full set of indicators should
        # still produce >=2 hits for a stable smuggling surface.
        base_url, base2 = await probe_url_async(str(ctx.host), "/")
        if not base2:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "refetch-base-failed"
            return finding
        chunk_resp = await _chunked_probe(base_url)
        indicators2, _ = _collect_indicators(base2, chunk_resp)
        if len(indicators2) >= 2:
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "refetch-indicators-stable"
            finding["verify_indicators"] = [i["kind"] for i in indicators2]
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = f"refetch-only-{len(indicators2)}-indicators"
            finding["verify_indicators"] = [i["kind"] for i in indicators2]
        return finding


def _r_smug(s):
    verified = s.get("methodology_findings") or []
    if not verified: return None
    confirmed = [f for f in verified if f.get("confidence") == "CONFIRMED"]
    if confirmed:
        return {"name": "HTTP request smuggling surface present (CONFIRMED)",
                "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-444",
                "evidence": confirmed[0]["evidence"],
                "remediation": "Disable HTTP/1.1 keep-alive between proxy and origin OR use "
                                "HTTP/2 end-to-end. Reject requests with both TE and CL."}
    return {"name": "Possible HTTP smuggling surface (SUSPECTED)",
            "severity": "LOW", "cvss": 3.1, "cwe": "CWE-444",
            "evidence": verified[0]["evidence"] + " - indicators flapped on refetch",
            "remediation": "Manually verify with HTTP smuggling test tools."}


FINDING_RULES = [_r_smug]
INTEL_FIELDS = [
    ("Server", "server_header"),
    ("Smuggling indicators", "smuggling_indicators"),
    ("Verified findings", "methodology_findings"),
    ("Stage timings (ms)", "stage_timings"),
]


@router.post("/api/vuln/http_request_smuggling")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = HttpRequestSmuggling()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
