"""webdav_exposure — WebDAV (PROPFIND / MKCOL) method exposure.

WebDAV extends HTTP with PROPFIND/PROPPATCH/MKCOL/MOVE/COPY/LOCK/UNLOCK
methods. If accidentally enabled, attacker can list directories,
upload files, even RCE via PUT then GET. IIS WebDAV CVE-2017-7269.
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()
PROBE_PATHS = ["/", "/dav/", "/webdav/", "/files/", "/upload/"]


@router.post("/api/webapp/scan/webdav_exposure")
@vl_turbo()
@vl_verify()
def scan_webdav_exposure(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    hits = []
    tested = 0
    for path in PROBE_PATHS:
        r = safe_request("PROPFIND", base + path,
            headers={"User-Agent": "VulnusLab/1.0", "Depth": "1",
                      "Content-Type": "application/xml"},
            data='<?xml version="1.0"?><propfind xmlns="DAV:"><prop/></propfind>',
            req=req, timeout=8, allow_redirects=False)
        if r is None: continue
        tested += 1
        if r.status_code == 207:  # Multi-Status = WebDAV
            hits.append({"path": path, "status": 207})
        elif r.status_code == 200 and "multistatus" in (r.text or "").lower():
            hits.append({"path": path, "status": 200})
    findings = []
    if hits:
        findings.append(wrap_finding(
            f"WebDAV ENABLED at {len(hits)} path(s)",
            "HIGH", cvss="8.6", cwe="CWE-732", owasp="A05:2021",
            remediation="Disable WebDAV unless required. nginx: don't include "
                        "ngx_http_dav_module. Apache: `Options -DAV`. IIS: "
                        "remove WebDAV Publishing role. WebDAV exposed = "
                        "directory traversal, arbitrary file upload, RCE via "
                        "PUT+GET on PHP/ASP paths.",
            evidence_marker=" | ".join(f"{h['path']}: HTTP {h['status']}" for h in hits[:5])))
    else:
        findings.append(wrap_finding(
            f"WebDAV not exposed ({tested} probes)", "POSITIVE", cwe="CWE-732",
            remediation="Maintain.", evidence_marker=f"{tested} PROPFIND probes rejected"))
    return standard_response(
        tool="webdav_exposure", target=req.target, findings=findings,
        tests_performed=tested, vulnerable=bool(hits),
        tests_summary=f"{tested} probes, {len(hits)} WebDAV enabled",
        raw_data={"hits": hits})


def register(app): app.include_router(router)
