"""XXE Injection - passive XML-acceptance + error detection. VL-METHOD Wave 2.

Refactored 2026-06-09 to MethodologyScanner. Surface-only - we never send a
real external entity (no SSRF, no DTD fetch). Verify step posts a SECOND
benign XML body with a different canary to confirm the endpoint genuinely
parses XML rather than echoing a static page.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import probe_url_async, http_post_async
from tools._vl_core.verify import vl_verify

router = APIRouter()

# Benign XML probes - no external entity. Two distinct canary names so we can
# confirm the second one shows up too.
PROBE_XML        = b'<?xml version="1.0"?><vlcanary>test</vlcanary>'
PROBE_XML_VERIFY = b'<?xml version="1.0"?><vlxxecheck>verify</vlxxecheck>'
CANARY_NAME        = "vlcanary"
CANARY_VERIFY_NAME = "vlxxecheck"

PROBE_PATHS_QUICK = ["/api/data", "/upload", "/import"]
PROBE_PATHS_DEEP  = ["/parse", "/feed", "/rss", "/xmlrpc.php", "/services/feeds"]

XML_ERROR_FPS = ["xml parsing", "xmlexception", "saxparseexception",
                  "invalid xml", "expected element", "lxml.etree",
                  "msxml", "system.xml.xmlexception", "no protocol"]


async def _fire(base_url, paths, xml_body, canary_name):
    accepting = []
    for path in paths:
        url = f"{base_url}{path}"
        r = await http_post_async(url, data=xml_body,
                                    headers={"Content-Type": "application/xml"},
                                    timeout=8)
        if not r:
            continue
        body_lower = r.get("body", "").lower()
        # Server echoes our canary OR returns XML
        if canary_name in body_lower or "<?xml" in body_lower:
            accepting.append({"path": path, "evidence": "echoed canary",
                               "status": r.get("status"), "canary": canary_name})
        # Or server returns XML parser error
        elif any(fp in body_lower for fp in XML_ERROR_FPS):
            accepting.append({"path": path, "evidence": "XML parser error",
                               "status": r.get("status"), "canary": canary_name})
    return accepting


class XxeInjection(MethodologyScanner):
    name = "xxe_injection"

    async def pre_flight(self, ctx):
        base_url, base = await probe_url_async(str(ctx.host), "/")
        if not base:
            ctx.state["tested"] = 0
            ctx.state["skipped_reason"] = "Target unreachable"
            return False
        ctx.source("http")
        ctx.state["tested"] = 1
        ctx.state["base_url"] = base_url
        ctx.state["probed_paths"] = len(PROBE_PATHS_QUICK) + len(PROBE_PATHS_DEEP)
        return True

    async def fingerprint(self, ctx):
        # No payload-side fingerprint for XXE - server header only
        from tools.vuln._vuln_common import http_get_async
        r = await http_get_async(ctx.state["base_url"], timeout=6)
        if r:
            hdrs = r.get("headers") or {}
            ctx.state["fingerprint"] = {
                "server": (hdrs.get("server") or "")[:80],
            }

    async def quick_probe(self, ctx):
        hits = await _fire(ctx.state["base_url"], PROBE_PATHS_QUICK,
                            PROBE_XML, CANARY_NAME)
        ctx.state["quick_hits"] = hits
        return [dict(h) for h in hits]

    async def deep_scan(self, ctx):
        hits = await _fire(ctx.state["base_url"], PROBE_PATHS_DEEP,
                            PROBE_XML, CANARY_NAME)
        ctx.state["deep_hits"] = hits
        return [dict(h) for h in hits]

    async def verify(self, ctx, finding):
        # Re-post a DIFFERENT XML body. Real XML parser echoes / errors on
        # both; static page echoing the first wouldn't echo the second.
        url = f"{ctx.state['base_url']}{finding['path']}"
        r = await http_post_async(url, data=PROBE_XML_VERIFY,
                                    headers={"Content-Type": "application/xml"},
                                    timeout=8)
        if not r:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "verify-probe-failed"
            return finding
        body_lower = r.get("body", "").lower()
        if CANARY_VERIFY_NAME in body_lower or \
           any(fp in body_lower for fp in XML_ERROR_FPS):
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "alt-xml-body-parsed"
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "alt-xml-body-not-parsed"
        return finding


def _r_xxe(s):
    verified = s.get("methodology_findings") or []
    if not verified:
        return None
    confirmed = [f for f in verified if f.get("confidence") == "CONFIRMED"]
    if confirmed:
        evidence = "; ".join(f"{f['path']} ({f['evidence']})" for f in confirmed)
        return {"name": f"{len(confirmed)} endpoint(s) parse XML (XXE surface, CONFIRMED)",
                "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-611",
                "evidence": f"Two distinct XML bodies both processed. {evidence}",
                "remediation": "Disable DOCTYPE/external entity expansion: "
                                'lxml(resolve_entities=False), Java DocumentBuilder.setFeature'
                                '("http://apache.org/xml/features/disallow-doctype-decl", true), '
                                ".NET XmlReaderSettings.DtdProcessing=Prohibit."}
    evidence = "; ".join(f"{f['path']} ({f['evidence']})" for f in verified)
    return {"name": f"{len(verified)} endpoint(s) MAY parse XML (XXE surface, SUSPECTED)",
            "severity": "LOW", "cvss": 3.1, "cwe": "CWE-611",
            "evidence": f"First XML body acknowledged but second didn't reproduce. {evidence}",
            "remediation": "Manually POST XML to each endpoint to verify parsing behaviour."}


FINDING_RULES = [_r_xxe]
INTEL_FIELDS = [
    ("Paths probed", "probed_paths"),
    ("Quick-probe hits", "quick_hits"),
    ("Deep-scan hits", "deep_hits"),
    ("Verified findings", "methodology_findings"),
    ("Stage timings (ms)", "stage_timings"),
]


@router.post("/api/vuln/xxe_injection")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = XxeInjection()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
