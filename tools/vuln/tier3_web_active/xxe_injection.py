"""XXE Injection - passive XML-acceptance + error detection. Self-contained.
Strategy: POST a benign XML body (no external entity!) to common endpoints, check if
server parses XML + returns XML errors that leak parser internals."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url_async, http_post_async

router = APIRouter()

# Benign XML probe — no external entity. We only check if the server PARSES XML.
PROBE_XML = b'<?xml version="1.0"?><vlcanary>test</vlcanary>'
PROBE_PATHS = ["/api/data", "/upload", "/import", "/parse", "/feed", "/rss",
                "/xmlrpc.php", "/services/feeds"]
XML_ERROR_FPS = ["xml parsing", "xmlexception", "saxparseexception",
                  "invalid xml", "expected element", "lxml.etree",
                  "msxml", "system.xml.xmlexception", "no protocol"]


async def gather(ctx):
    host = str(ctx.host)
    base_url, base = await probe_url_async(host, "/")
    if not base:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    ctx.state["probed_paths"] = len(PROBE_PATHS)
    accepting = []
    for path in PROBE_PATHS:
        url = f"{base_url}{path}"
        r = await http_post_async(url, data=PROBE_XML, headers={"Content-Type": "application/xml"}, timeout=8)
        if not r:
            continue
        body_lower = r.get("body", "").lower()
        # Check 1: server echoes our XML or returns XML response (parses XML)
        if "vlcanary" in body_lower or "<?xml" in body_lower:
            accepting.append({"path": path, "evidence": "echoed canary", "status": r.get("status")})
        # Check 2: server returns XML parser error (also indicates XML parsing)
        elif any(fp in body_lower for fp in XML_ERROR_FPS):
            accepting.append({"path": path, "evidence": "XML parser error", "status": r.get("status")})
    ctx.state["xml_accepting_endpoints"] = accepting


def _r_xxe(s):
    accepting = s.get("xml_accepting_endpoints") or []
    if not accepting:
        return None
    # Surface area only — flag as MEDIUM since we can't safely confirm XXE without sending external entity
    return {"name": f"{len(accepting)} endpoint(s) accept XML (XXE surface)",
            "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-611",
            "evidence": "; ".join(f"{a['path']} ({a['evidence']})" for a in accepting),
            "remediation": "Disable DOCTYPE/external entity expansion: lxml(resolve_entities=False), Java DocumentBuilder.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true), .NET XmlReaderSettings.DtdProcessing=Prohibit."}


FINDING_RULES = [_r_xxe]
INTEL_FIELDS = [("Paths probed", "probed_paths"), ("XML-accepting", "xml_accepting_endpoints")]


@router.post("/api/vuln/xxe_injection")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="xxe_injection",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
