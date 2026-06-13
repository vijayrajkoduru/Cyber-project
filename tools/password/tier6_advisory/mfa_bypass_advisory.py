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
authorization. This endpoint returns an honest INFO advisory via the
canonical run_scanner + FINDING_RULES pattern (never graded above INFO).
"""
from __future__ import annotations
from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools.password.tier6_advisory.mfa_bypass_advisory_findings import (
    MFA_BYPASS_ADVISORY_FINDING_RULES,
)

router = APIRouter()

TITLE = "Modern auth bypass execution (MFA fatigue / OTP brute / EvilGinx) - §8"
REASON = (
    "Executing MFA fatigue / push bombing, OTP brute force, SIM swap, "
    "push-token hijack, passkey downgrade, or EvilGinx2/Modlishka/BitB "
    "phishing are ACTIVE attacks against users, carriers, and live auth "
    "flows - out of scope for a detection-only (VA, not PT) scanner and "
    "requiring explicit engagement authorization. The POSTURE side (MFA / "
    "WebAuthn / passkey presence, unthrottled OTP endpoints) IS probed "
    "live by mfa_passkey_surface_audit."
)


async def gather(ctx: ScanContext):
    ctx.state["advisory"] = True
    ctx.state["advisory_title"] = TITLE
    ctx.state["advisory_reason"] = REASON
    ctx.state["advisory_cwe"] = "CWE-308"
    # Real source attribution: advisory-by-design, derived from the
    # playbook §8 catalogue, NOT from a live scan of the target.
    ctx.source("advisory-by-design (active execution attacks, detection-only scanner out of scope)")


INTEL_FIELDS = [("§8 Modern auth bypass execution", "advisory_title")]


@router.post("/api/password/mfa_bypass_advisory")
async def mfa_bypass_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target,
        tool="mfa_bypass_advisory",
        gather_func=gather,
        finding_rules=MFA_BYPASS_ADVISORY_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
