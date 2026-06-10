"""Webapp: Swagger/OpenAPI spec discovery.

VL-VERIFY: existing JSON-validation gate (must parse as dict + have
'swagger'/'openapi'/'paths' key) already filters most SPA-shell FPs.
Belt-and-braces: stamp spa_catchall + suppress when SPA canary returns
the same body that the spec path returned (means the path didn't really
exist - SPA catch-all served the shell).
"""
import json
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response
from tools._framework.spa_canary import detect_spa_catchall_sync, is_same_as_canary

router = APIRouter()

_SPEC_PATHS = [
    "/swagger.json","/swagger.yaml","/openapi.json","/openapi.yaml",
    "/api/swagger.json","/api/openapi.json","/api/swagger",
    "/v1/swagger.json","/v2/swagger.json","/v3/swagger.json",
    "/api/v1/swagger.json","/api/v2/swagger.json","/api/v3/swagger.json",
    "/api-docs","/api/docs","/swagger-ui","/swagger-ui.html",
    "/swagger/v1/swagger.json","/api-docs.json","/api/spec",
]


@router.post("/api/webapp/swagger_discovery")
async def webapp_swagger_discovery(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    spa = detect_spa_catchall_sync(base)
    findings = []
    discovered = []
    spa_suppressed = []
    for path in _SPEC_PATHS:
        r = safe_get(base + path, req=req, allow_redirects=True, timeout=8)
        if r is None or r.status_code != 200:
            continue
        # SPA catch-all: body matches canary -> path doesn't exist
        if spa["is_spa"] and is_same_as_canary(r.text or "", spa["canary_body"]):
            spa_suppressed.append(path)
            continue
        try:
            data = json.loads(r.text)
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        if not (("swagger" in data or "openapi" in data) or "paths" in data):
            continue
        api_paths = list((data.get("paths", {}) or {}).keys())
        discovered.append({"url": path, "endpoint_count": len(api_paths), "first_5": api_paths[:5]})
        findings.append(wrap_finding(
            f"OpenAPI/Swagger spec exposed at {path} ({len(api_paths)} endpoints documented)",
            "MEDIUM",
            cvss="5.3", cwe="CWE-200", cwe_name="Information Exposure",
            owasp="A05:2021",
            remediation=f"Restrict access to API documentation in production. Block {path} or require authentication.",
            evidence_marker=f"GET {path} returned valid OpenAPI spec with {len(api_paths)} endpoints",
        ))

    tests_summary = f"Tested {len(_SPEC_PATHS)} common Swagger paths; {len(discovered)} exposed"
    if spa_suppressed:
        tests_summary += f"; {len(spa_suppressed)} SPA-shell paths suppressed"
    return standard_response(
        tool="swagger_discovery", target=req.target,
        findings=findings, tests_performed=len(_SPEC_PATHS),
        tests_summary=tests_summary,
        raw_data={"swagger_discovery": {"discovered": discovered,
                                          "spa_catchall": spa["is_spa"],
                                          "spa_suppressed_paths": spa_suppressed}},
    )


def register(app):
    app.include_router(router)
