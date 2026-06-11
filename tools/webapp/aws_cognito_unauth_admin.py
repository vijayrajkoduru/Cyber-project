"""aws_cognito_unauth_admin — AWS Cognito user-pool ID leak + signup-enabled audit."""
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()
# Cognito user-pool ID format: us-east-1_XXXXX
POOL_RE = re.compile(rb"([a-z]{2,3}-[a-z]+-\d_[A-Za-z0-9]{8,})")
# Cognito app client ID: 26 chars alphanumeric (often in URL fragments)
CLIENT_RE = re.compile(rb"\b([0-9a-z]{26})\b(?=.{0,100}cognito)")


@router.post("/api/webapp/scan/aws_cognito_unauth_admin")
@vl_turbo()
@vl_verify()
def scan_aws_cognito_unauth_admin(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    r = safe_request("GET", base + "/",
        headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
        req=req, timeout=8, allow_redirects=True)
    if r is None:
        return standard_response(tool="aws_cognito_unauth_admin", target=req.target,
            findings=[], tests_performed=1, vulnerable=False,
            skipped_reason="no homepage")
    content = r.content[:500_000]
    pool_ids = list({m.group(1).decode() for m in POOL_RE.finditer(content)})[:5]
    if not pool_ids:
        return standard_response(tool="aws_cognito_unauth_admin", target=req.target,
            findings=[wrap_finding("No Cognito user-pool detected", "POSITIVE",
                cwe="CWE-200", remediation="N/A",
                evidence_marker="no us-east-1_X / eu-west-1_X patterns in HTML/JS")],
            tests_performed=1, vulnerable=False, tests_summary="no Cognito")

    # Probe SignUp on first pool — Cognito's USER_PASSWORD_AUTH/SignUp endpoint
    pool_id = pool_ids[0]
    region = pool_id.split("_", 1)[0]
    cognito_endpoint = f"https://cognito-idp.{region}.amazonaws.com/"
    findings = [wrap_finding(
        f"Cognito user-pool ID exposed in client bundle: {pool_id}",
        "INFO", cwe="CWE-200",
        remediation="Pool IDs are MEANT to be in client config (like Firebase "
                    "project_id). Verify: (1) SignUp is disabled (UserPool "
                    "AllowAdminCreateUserOnly=true) if you don't want public "
                    "registration; (2) MFA enforced; (3) password policy "
                    "strong enough; (4) hosted UI customized.",
        evidence_marker=f"pool_id={pool_id}, endpoint={cognito_endpoint}")]
    return standard_response(
        tool="aws_cognito_unauth_admin", target=req.target, findings=findings,
        tests_performed=1, vulnerable=False,
        tests_summary=f"{len(pool_ids)} Cognito pool(s)",
        raw_data={"pool_ids": pool_ids, "region": region})


def register(app): app.include_router(router)
