"""crlf_header_injection_deep — CRLF in Set-Cookie / Location / Custom-Header values.

Existing crlf_injection scanner tests path/query CRLF. This one tests
CRLF reflection INTO HEADER VALUES via path-param echo (e.g., User-Agent
echoed into response, Cookie value echoed, redirect URL echoed). If
attacker can inject \\r\\n into a header response, they can:
  - Set arbitrary cookies (Cookie tossing)
  - Set arbitrary response headers (CORS spoof, CSP bypass)
  - Split response (legacy attack but still works on naive backends)
"""
from urllib.parse import quote
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

# (description, payload)
PAYLOADS = [
    ("classic CRLF",       "%0d%0aSet-Cookie:%20vulnuslab=injected"),
    ("CR-only (HTTP/1.0)",  "%0dSet-Cookie:%20vulnuslab=injected"),
    ("LF-only",             "%0aSet-Cookie:%20vulnuslab=injected"),
    ("nullbyte+CRLF",       "%00%0d%0aSet-Cookie:%20vulnuslab=injected"),
    ("Unicode CRLF",        "%c0%8d%c0%8aSet-Cookie:%20vulnuslab=injected"),
]
PROBE_PATHS = [
    "/", "/?next=", "/?redirect=", "/?lang=", "/?country=",
    "/redirect", "/redirect?url=",
]


@router.post("/api/webapp/scan/crlf_header_injection_deep")
@vl_turbo()
@vl_verify()
def scan_crlf_header_injection_deep(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    confirmed = []
    tested = 0

    for path in PROBE_PATHS:
        for desc, pl in PAYLOADS:
            # Append payload as path/query suffix
            url = base + path + pl
            r = safe_request("GET", url,
                headers={"User-Agent": "VulnusLab/1.0"},
                req=req, timeout=8, allow_redirects=False)
            if r is None: continue
            tested += 1
            # Check if our injected Set-Cookie made it into response
            try:
                cookies_raw = r.headers.get("set-cookie", "")
            except Exception:
                cookies_raw = ""
            if "vulnuslab=injected" in cookies_raw:
                confirmed.append({"path": path, "payload_type": desc,
                                    "payload": pl[:60],
                                    "injected_header": "Set-Cookie"})
                break  # one per path

    findings = []
    if confirmed:
        findings.append(wrap_finding(
            f"CRLF HEADER INJECTION confirmed at {len(confirmed)} location(s)",
            "HIGH", cvss="7.5", cwe="CWE-113", owasp="A03:2021",
            remediation="The server reflects user-controlled CRLF into response "
                        "headers. Strip \\r and \\n from any value flowing into "
                        "headers BEFORE adding them. Most frameworks block this "
                        "via stdlib (Python http.server, Node Express) — bug is "
                        "usually in custom redirect handlers or proxy plugins. "
                        "Reference: OWASP HTTP Response Splitting.",
            evidence_marker=" | ".join(
                f"{c['path']} ({c['payload_type']}) → Set-Cookie injected"
                for c in confirmed[:5]
            )))
    elif tested > 0:
        findings.append(wrap_finding(
            f"No CRLF header injection across {tested} probe(s)",
            "POSITIVE", cwe="CWE-113",
            remediation="Maintain. Continue testing new endpoints with CRLF "
                        "payloads when adding redirect/proxy logic.",
            evidence_marker=f"{tested} tests across {len(PROBE_PATHS)} paths × "
                              f"{len(PAYLOADS)} payloads"))
    else:
        return standard_response(
            tool="crlf_header_injection_deep", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="No responses received")

    return standard_response(
        tool="crlf_header_injection_deep", target=req.target, findings=findings,
        tests_performed=len(PROBE_PATHS) * len(PAYLOADS),
        vulnerable=bool(confirmed),
        tests_summary=f"{tested} probes, {len(confirmed)} confirmed injections",
        raw_data={"confirmed_injections": confirmed})


def register(app):
    app.include_router(router)
