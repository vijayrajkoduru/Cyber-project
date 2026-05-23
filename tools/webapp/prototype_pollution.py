"""Webapp: Prototype Pollution detection (Node.js)."""
import secrets
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response

router = APIRouter()


@router.post("/api/webapp/prototype_pollution")
async def webapp_prototype_pollution(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    tests = 0
    canary = secrets.token_hex(8)
    
    payloads = [
        f"__proto__[ppMarker]={canary}",
        f"__proto__.ppMarker={canary}",
        f"constructor[prototype][ppMarker]={canary}",
        f"constructor.prototype.ppMarker={canary}",
    ]
    
    suspect = []
    for p in payloads:
        tests += 1
        # Send pollution payload
        r1 = safe_get(f"{base}/?{p}", req=req, timeout=8)
        if r1 is None:
            continue
        # Fetch a different endpoint to check if pollution persisted
        r2 = safe_get(f"{base}/api/config", req=req, timeout=6) or safe_get(f"{base}/health", req=req, timeout=6)
        if r2 is None:
            continue
        # If canary appears in unrelated endpoint response, pollution worked
        if canary in (r2.text or ""):
            suspect.append({"payload": p, "leaked_at": r2.url if hasattr(r2,"url") else "unknown"})
            findings.append(wrap_finding(
                f"Prototype Pollution confirmed via '{p}' - canary leaked to unrelated endpoint",
                "HIGH",
                cvss="8.1", cwe="CWE-1321",
                cwe_name="Improperly Controlled Modification of Object Prototype Attributes",
                owasp="A08:2021",
                remediation="Use Object.create(null) for user-controlled object merging. Validate keys against allow-list. Upgrade lodash >= 4.17.12, jQuery >= 3.5.0.",
                evidence_marker=f"GET ?{p} -> canary '{canary}' appeared in subsequent /api/config or /health response",
            ))
            break

    return standard_response(
        tool="prototype_pollution", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"{tests} prototype pollution probes with unique canary",
        raw_data={"prototype_pollution": {"canary": canary, "suspect": suspect}},
    )


def register(app):
    app.include_router(router)
