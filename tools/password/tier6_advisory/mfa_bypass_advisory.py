"""mfa_bypass_advisory - §8 Modern Auth Bypass execution (advisory-by-design).

module_playbooks/08_password.md §8 lists 10 modern-auth BYPASS techniques
(MFA fatigue / push bombing, OTP brute, TOTP secret extraction, SIM swap,
push-token hijack, WebAuthn/passkey enumeration, passkey downgrade,
EvilGinx2 / Modlishka phishing, browser-in-the-browser phishing).

The DETECTION/posture side of this section (does the app offer WebAuthn /
passkeys / MFA, is an OTP endpoint reachable without throttling) IS probed
live by tier5_web/mfa_passkey_surface_audit. The EXECUTION techniques here -
push bombing, OTP brute force, SIM swap, phishing toolkits - are active
attacks against users / carriers / real authentication flows. They are
out of scope for a detection-only (VA, not PT) SaaS scanner and require
manual / social-engineering / red-team execution under explicit engagement
authorization. This endpoint returns an honest INFO advisory.
"""
from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._pack_common import _advisory_by_design_response

router = APIRouter()


@router.post("/api/password/mfa_bypass_advisory")
def mfa_bypass_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _advisory_by_design_response(
        tool="mfa_bypass_advisory",
        target=req.target,
        title="Modern auth bypass execution (MFA fatigue / OTP brute / EvilGinx) - §8",
        reason=(
            "Executing MFA fatigue / push bombing, OTP brute force, SIM swap, "
            "push-token hijack, passkey downgrade, or EvilGinx2/Modlishka/BitB "
            "phishing are ACTIVE attacks against users, carriers, and live auth "
            "flows - out of scope for a detection-only (VA, not PT) scanner and "
            "requiring explicit engagement authorization. The POSTURE side (MFA / "
            "WebAuthn / passkey presence, unthrottled OTP endpoints) IS probed "
            "live by mfa_passkey_surface_audit."
        ),
        cwe="CWE-308",
    )


def register(app):
    app.include_router(router)
