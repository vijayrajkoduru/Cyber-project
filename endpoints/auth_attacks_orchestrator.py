"""auth_attacks module orchestrator - modern web/SaaS auth attack probes.

Per module_playbooks/17_auth_attacks.md - 7 sections, 74 techniques.
Scanner set (real remote/offline probes + honest advisory-by-design):
  - tier1_token  (§5 JWT / §4 SAML):
        jwt_secret_audit, saml_signature_audit, jwks_exposure_audit
  - tier2_flow   (§3 OAuth / OIDC / §2 session):
        oauth_redirect_audit, session_fixation_test,
        oidc_discovery_audit, oauth_token_replay_audit
  - tier3_mfa    (§2 MFA Bypass):
        mfa_bypass_test, okta_password_policy_audit
  - tier4_saml   (§4 SAML / Federation):
        saml_metadata_audit
  - tier5_passkey (§7 Passwordless / WebAuthn):
        webauthn_config_audit, magic_link_entropy_audit
  - tier6_advisory (§1 PtX / §6 Kerberos / §2 phishing - non-SaaS-probeable):
        auth_attacks_advisory_pack  ([ADVISORY-BY-DESIGN] INFO only)

Graded severities (CRITICAL/HIGH/MEDIUM/LOW) are emitted ONLY when a probe
actually detected the condition on the live target; everything advisory or
input-required is INFO. No exploitation, no chaining between scanners.

Concurrency is intentionally LOW (3) because every probe hammers the
customer's auth flow with mutated requests; running more than three
concurrently against a single live IdP / SSO tenant trips rate-limits
+ lockouts and pollutes the result set.
"""
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_parallel, run_module_streaming

router = APIRouter()


AUTH_ATTACKS_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_token": [
        ("jwt_secret_audit",       "/api/auth_attacks/jwt_secret_audit"),
        ("saml_signature_audit",   "/api/auth_attacks/saml_signature_audit"),
        ("jwks_exposure_audit",    "/api/auth_attacks/jwks_exposure_audit"),
    ],
    "tier2_flow": [
        ("login_discovery_audit",  "/api/auth_attacks/login_discovery_audit"),
        ("oauth_redirect_audit",   "/api/auth_attacks/oauth_redirect_audit"),
        ("session_fixation_test",  "/api/auth_attacks/session_fixation_test"),
        ("oidc_discovery_audit",   "/api/auth_attacks/oidc_discovery_audit"),
        ("oauth_token_replay_audit", "/api/auth_attacks/oauth_token_replay_audit"),
    ],
    "tier3_mfa": [
        ("mfa_bypass_test",        "/api/auth_attacks/mfa_bypass_test"),
        ("okta_password_policy_audit", "/api/auth_attacks/okta_password_policy_audit"),
    ],
    "tier4_saml": [
        ("saml_metadata_audit",    "/api/auth_attacks/saml_metadata_audit"),
    ],
    "tier5_passkey": [
        ("webauthn_config_audit",  "/api/auth_attacks/webauthn_config_audit"),
        ("magic_link_entropy_audit", "/api/auth_attacks/magic_link_entropy_audit"),
    ],
    "tier6_advisory": [
        ("auth_attacks_advisory_pack", "/api/auth_attacks/auth_attacks_advisory_pack"),
    ],
}


def _all_tools():
    out = []
    for tier in AUTH_ATTACKS_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class AuthAttacksRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 3
    # Authenticated context — token/session/IDOR-style checks behind login.
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None
    options: Optional[dict] = None


def _resolve(req: AuthAttacksRunAllRequest, request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in AUTH_ATTACKS_TOOLS_BY_TIER:
                tools.extend(AUTH_ATTACKS_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    # Nest the customer options dict so each scanner can read it via
    # req.options (the orchestrator flattens extra_body into the per-tool body).
    extra: dict = {}
    if req.options:
        extra["options"] = req.options
    return tools, extra or None, jwt


@router.post("/api/auth_attacks/run_all")
async def auth_attacks_run_all(req: AuthAttacksRunAllRequest, request: Request,
                                _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    # Hard-clamp concurrency to 3 (auth module rule - avoid IdP lockout).
    concurrency = max(1, min(req.concurrency or 3, 3))
    gen = run_module_streaming(
        target=req.target, tools=tools, module_name="auth_attacks",
        concurrency=concurrency, auth_cookie=req.auth_cookie,
        auth_bearer=req.auth_bearer, extra_body=extra, jwt_token=jwt,
    )
    return StreamingResponse(
        gen,
        media_type="application/x-ndjson",
        headers={
            "X-Accel-Buffering": "no",
            "Cache-Control":     "no-store, no-transform",
            "Connection":        "keep-alive",
        },
    )


@router.post("/api/auth_attacks/run_all_buffered")
async def auth_attacks_run_all_buffered(req: AuthAttacksRunAllRequest, request: Request,
                                         _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 3, 3))
    return await run_module_parallel(
        target=req.target, tools=tools, module_name="auth_attacks",
        concurrency=concurrency, extra_body=extra, jwt_token=jwt,
    )


@router.get("/api/auth_attacks/run_all/tiers")
async def auth_attacks_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in AUTH_ATTACKS_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in AUTH_ATTACKS_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
