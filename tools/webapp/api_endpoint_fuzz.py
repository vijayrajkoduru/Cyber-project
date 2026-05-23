"""Webapp: API endpoint fuzz - discovers Swagger spec, fuzzes each endpoint with bad inputs."""
import json
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response

router = APIRouter()

_SPEC_PATHS = ["/swagger.json","/openapi.json","/api/swagger.json","/api/openapi.json","/v1/swagger.json","/v2/swagger.json","/v3/swagger.json","/api-docs","/api-docs.json"]
_FUZZ_VALUES = ["", "0", "-1", "null", "{}", "[]", "'", '"', "../../etc/passwd", "999999"]


@router.post("/api/webapp/api_endpoint_fuzz")
async def webapp_api_endpoint_fuzz(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    tests = 0
    # 1) Find Swagger spec
    spec = None
    for sp in _SPEC_PATHS:
        tests += 1
        r = safe_get(base + sp, req=req, allow_redirects=True, timeout=8)
        if r is None or r.status_code != 200:
            continue
        try:
            d = json.loads(r.text)
            if isinstance(d, dict) and ("paths" in d):
                spec = d
                break
        except Exception:
            continue
    if not spec:
        return standard_response(
            tool="api_endpoint_fuzz", target=req.target, findings=[],
            tests_performed=tests, skipped_reason="No OpenAPI/Swagger spec discovered",
        )
    
    # 2) For each GET endpoint, probe with fuzzed query params + check for 5xx/stack-trace
    paths = list(spec.get("paths", {}).items())[:20]  # cap to 20 paths
    crashes = []
    for path, methods in paths:
        if "get" not in (k.lower() for k in (methods.keys() if isinstance(methods, dict) else [])):
            continue
        # Build URL by replacing path params with "1"
        url = path
        for tok in path.split("/"):
            if tok.startswith("{") and tok.endswith("}"):
                url = url.replace(tok, "1")
        for val in _FUZZ_VALUES:
            tests += 1
            full = f"{base}{url}?fuzz={val}"
            r = safe_get(full, req=req, timeout=6)
            if r is None:
                continue
            if r.status_code >= 500:
                body = (r.text or "")[:5000].lower()
                if any(s in body for s in ("traceback","exception","stack trace","at line","sqlexception","mysql","postgresql")):
                    crashes.append({"endpoint": path, "fuzz": val, "status": r.status_code})
                    findings.append(wrap_finding(
                        f"API endpoint {path} crashes (5xx + stack trace) on fuzz input '{val}'",
                        "HIGH",
                        cvss="7.5", cwe="CWE-209",
                        cwe_name="Generation of Error Message Containing Sensitive Information",
                        owasp="A05:2021",
                        remediation="Return generic 4xx for bad input, NEVER expose stack traces or DB errors to clients. Log internally only.",
                        evidence_marker=f"GET {full} -> HTTP {r.status_code} with stack trace in body",
                    ))
                    break

    return standard_response(
        tool="api_endpoint_fuzz", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Fuzzed {len(paths)} Swagger-discovered endpoints with {len(_FUZZ_VALUES)} bad inputs",
        raw_data={"api_endpoint_fuzz": {"crashes": crashes, "spec_endpoints": len(paths)}},
    )


def register(app):
    app.include_router(router)
