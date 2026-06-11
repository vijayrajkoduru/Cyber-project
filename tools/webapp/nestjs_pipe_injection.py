"""nestjs_pipe_injection — NestJS pipe validation bypass + version disclosure.

NestJS apps that don't enable ValidationPipe globally have routes
accepting unvalidated body — mass assignment + prototype pollution
chains. Detect NestJS footprint + missing global validation.
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()


@router.post("/api/webapp/scan/nestjs_pipe_injection")
@vl_turbo()
@vl_verify()
def scan_nestjs_pipe_injection(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    r = safe_request("GET", base + "/",
        headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
        req=req, timeout=8, allow_redirects=True)
    if r is None:
        return standard_response(tool="nestjs_pipe_injection", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason="no response")
    body = r.text or ""
    # NestJS signature: X-Powered-By: Express + NestJS classnames in error pages
    is_nest = ("nestjs" in body.lower() or
                "X-Powered-By" in r.headers and "Express" in (r.headers.get("X-Powered-By", "")))
    # NestJS often exposes Swagger at /api or /docs by default
    has_swagger_api = False
    sw = safe_request("GET", base + "/api", headers={"User-Agent": "VulnusLab/1.0"},
        req=req, timeout=6, allow_redirects=False)
    if sw is not None and sw.status_code == 200 and ("swagger" in (sw.text or "").lower() or
                                                      "openapi" in (sw.text or "").lower()):
        has_swagger_api = True

    findings = []
    if has_swagger_api:
        findings.append(wrap_finding(
            "NestJS Swagger UI exposed at /api (default route)",
            "MEDIUM", cvss="5.3", cwe="CWE-200", owasp="A05:2021",
            remediation="Move Swagger to non-default authenticated path in prod. "
                        "Disable entirely if not needed: don't call SwaggerModule"
                        ".setup() in production NestJS bootstrap. Default /api "
                        "exposes schema to anyone.",
            evidence_marker="GET /api → Swagger/OpenAPI content"))
    elif is_nest:
        findings.append(wrap_finding(
            "NestJS detected — manually verify ValidationPipe is global",
            "INFO", cwe="CWE-915",
            remediation="In main.ts: app.useGlobalPipes(new ValidationPipe({"
                        " whitelist: true, forbidNonWhitelisted: true })). "
                        "'whitelist: true' strips unknown props (mass-assignment "
                        "defense). 'forbidNonWhitelisted' returns 400 instead. "
                        "Without these, attacker mass-assigns isAdmin / role.",
            evidence_marker="NestJS signature present"))
    else:
        findings.append(wrap_finding(
            "Not NestJS — no specific audit needed", "POSITIVE", cwe="CWE-1395",
            remediation="N/A", evidence_marker="no NestJS footprint"))
    return standard_response(
        tool="nestjs_pipe_injection", target=req.target, findings=findings,
        tests_performed=2, vulnerable=has_swagger_api,
        tests_summary=f"nestjs={is_nest}, swagger_api={has_swagger_api}",
        raw_data={"is_nest": is_nest, "swagger_at_api": has_swagger_api})


def register(app): app.include_router(router)
