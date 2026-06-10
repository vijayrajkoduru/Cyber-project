"""Webapp: File upload endpoint discovery + bypass technique enumeration."""
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response
from tools._vl_core.spa_canary import detect_spa_catchall_sync
from tools._vl_core.verify import vl_verify

router = APIRouter()

_UPLOAD_PATHS = ["/upload","/api/upload","/file/upload","/files/upload","/images/upload","/admin/upload","/user/upload","/api/v1/upload"]

# AI-curated 80-entry list of (filename, content-type, technique, severity)
try:
    from tools._payloads.file_upload_bypass_extensions import FILE_UPLOAD_BYPASS_EXTENSIONS as _AI_BYPASS
    _AI_BYPASS = _AI_BYPASS if isinstance(_AI_BYPASS, list) else []
except Exception:
    _AI_BYPASS = []


@router.post("/api/webapp/file_upload_bypass")
@vl_verify()
async def webapp_file_upload_bypass(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    spa = detect_spa_catchall_sync(base)
    findings = []
    discovered = []
    tests = 0
    
    # Phase 1: discover endpoints
    for path in _UPLOAD_PATHS:
        tests += 1
        r = safe_get(base + path, req=req, allow_redirects=True, timeout=8)
        if r is None or r.status_code == 404:
            continue
        body = (r.text or "")[:30000]
        if not re.search(r'<input[^>]*type=["\']?file["\']?', body, re.I):
            continue
        # Check what's allowed
        accept = re.search(r'<input[^>]*accept=["\']?([^"\']*)["\']?', body, re.I)
        accept_val = accept.group(1) if accept else "any"
        max_size = re.search(r'name=["\']?MAX_FILE_SIZE["\']?[^>]*value=["\']?([0-9]+)', body, re.I)
        max_val = max_size.group(1) if max_size else None
        discovered.append({"url": path, "accept": accept_val, "max_size": max_val})
        findings.append(wrap_finding(
            f"File upload endpoint discovered at {path}",
            "MEDIUM",
            cvss="5.4", cwe="CWE-434",
            cwe_name="Unrestricted Upload of File with Dangerous Type",
            owasp="A04:2021",
            remediation="Server-side: validate file content type (magic bytes), reject executable extensions (.php/.jsp/.asp/.exe), store outside web root, rename uploads, scan with AV. Client-side accept attribute is NOT a security control.",
            evidence_marker=f"GET {path} - file input found; client-side accept='{accept_val}'" + (f", max_size={max_val}" if max_val else ""),
        ))

    return standard_response(
        tool="file_upload_bypass", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Probed {tests} common upload paths; {len(discovered)} endpoint(s) found",
        raw_data={"file_upload_bypass": {"endpoints": discovered, "spa_catchall": spa["is_spa"]}},
    )


def register(app):
    app.include_router(router)
