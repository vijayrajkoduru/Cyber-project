"""postman_api_discovery — leaked Postman docs / OpenAPI spec discovery."""
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()
DOC_PATHS = [
    "/postman", "/postman.json", "/api/postman.json",
    "/docs", "/api-docs", "/swagger.json", "/openapi.json",
    "/v3/api-docs", "/v2/api-docs", "/.well-known/openapi",
    "/redoc", "/api/spec",
]


@router.post("/api/webapp/scan/postman_api_discovery")
@vl_turbo()
@vl_verify()
def scan_postman_api_discovery(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")

    def _probe(path):
        r = safe_request("GET", base + path,
            headers={"User-Agent": "VulnusLab/1.0",
                      "Accept": "application/json"},
            req=req, timeout=6, allow_redirects=False)
        if r is None or r.status_code != 200: return None
        body = (r.text or "")[:50000]
        markers = ["postman_collection", "swagger", "openapi", "schemes"]
        if any(m in body.lower() for m in markers):
            return {"path": path, "size": len(body),
                    "kind": "postman" if "postman_collection" in body.lower()
                    else "openapi"}
        return None

    leaks = []
    # VL-TURBO deep: parallelize 11 probes via pool(10).
    # Was ~66s sequential, now ~6s parallel.
    with ThreadPoolExecutor(max_workers=min(10, len(DOC_PATHS))) as pool:
        for result in pool.map(_probe, DOC_PATHS, timeout=17):
            if result is not None:
                leaks.append(result)
    findings = []
    if leaks:
        findings.append(wrap_finding(
            f"API documentation EXPOSED at {len(leaks)} path(s)",
            "MEDIUM", cvss="5.3", cwe="CWE-200", owasp="A05:2021",
            remediation="API docs reveal every endpoint + params + auth schemes "
                        "to attackers. Production: gate behind auth OR move to "
                        "internal-only domain. For public-API products, OK to "
                        "expose curated docs but NOT the raw OpenAPI JSON "
                        "(too much detail).",
            evidence_marker=" | ".join(
                f"{l['path']}: {l['kind']} spec ({l['size']}B)" for l in leaks[:5]
            )))
    else:
        findings.append(wrap_finding(
            "No exposed API documentation",
            "POSITIVE", cwe="CWE-200",
            remediation="Maintain.",
            evidence_marker=f"checked {len(DOC_PATHS)} common doc paths"))
    return standard_response(
        tool="postman_api_discovery", target=req.target, findings=findings,
        tests_performed=len(DOC_PATHS), vulnerable=bool(leaks),
        tests_summary=f"{len(leaks)} doc paths exposed",
        raw_data={"leaks": leaks})


def register(app): app.include_router(router)
