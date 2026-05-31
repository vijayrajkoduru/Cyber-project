"""trino_metadata_leak — Trino /ui/api/cluster + /v1/info catalog enumeration."""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)

router = APIRouter()
META_PATHS = ["/v1/info", "/ui/api/cluster", "/v1/catalog", "/v1/node"]


@router.post("/api/webapp/scan/trino_metadata_leak")
def scan_trino_metadata_leak(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    leaks = []
    for path in META_PATHS:
        r = safe_request("GET", base + path,
            headers={"User-Agent": "VulnusLab/1.0",
                      "Accept": "application/json"},
            req=req, timeout=8, allow_redirects=False)
        if r is None or r.status_code != 200: continue
        body = (r.text or "")[:5000]
        if "trino" in body.lower() or "presto" in body.lower() or "nodeId" in body:
            leaks.append({"path": path, "snippet": body[:200]})
    findings = []
    if leaks:
        findings.append(wrap_finding(
            f"Trino metadata leaked at {len(leaks)} endpoint(s)",
            "HIGH", cvss="7.5", cwe="CWE-200", owasp="A05:2021",
            remediation="Trino's /v1/info + /ui/api/cluster expose version + "
                        "node topology + connected catalogs. Internal-only. "
                        "Configure Trino to require auth on ALL paths including "
                        "/ui/. Internet-exposed Trino metadata = reconnaissance "
                        "preamble to data theft.",
            evidence_marker=" | ".join(f"{l['path']}: 200" for l in leaks[:3])))
    else:
        findings.append(wrap_finding("No Trino metadata exposed", "POSITIVE",
            cwe="CWE-200", remediation="Maintain.",
            evidence_marker=f"checked {len(META_PATHS)} Trino meta paths"))
    return standard_response(
        tool="trino_metadata_leak", target=req.target, findings=findings,
        tests_performed=len(META_PATHS), vulnerable=bool(leaks),
        tests_summary=f"{len(leaks)} metadata endpoints leaked",
        raw_data={"leaks": leaks})


def register(app): app.include_router(router)
