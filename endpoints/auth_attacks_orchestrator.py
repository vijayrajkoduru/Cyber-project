"""Auth Attacks module orchestrator — 17_auth_attacks.md (74 endpoints)."""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_streaming
from tools.auth_attacks.auth_attacks_pack import TECHNIQUES

router = APIRouter()

_SECTION_RANGES = [
    ("tier1_pass_the_x",     0, 10),
    ("tier2_mfa_bypass",     10, 22),
    ("tier3_oauth_oidc",     22, 36),
    ("tier4_saml_federation",36, 44),
    ("tier5_jwt_attacks",    44, 54),
    ("tier6_kerberos",       54, 64),
    ("tier7_passwordless",   64, 74),
]

AUTH_ATTACKS_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    tier_id: [(t[0], f"/api/auth_attacks/{t[0]}") for t in TECHNIQUES[a:b]]
    for tier_id, a, b in _SECTION_RANGES
}


class AuthAttacksRunAllRequest(BaseModel):
    target: str
    concurrency: Optional[int] = 16
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None


def _all_tools():
    out = []
    for tools in AUTH_ATTACKS_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


@router.post("/api/auth_attacks/run_all")
async def auth_attacks_run_all(req: AuthAttacksRunAllRequest, request: Request,
                                _=Depends(verify_scan_quota)):
    jwt_token = request.headers.get("authorization", "").replace("Bearer ", "") or None
    generator = run_module_streaming(target=req.target, tools=_all_tools(),
        module_name="auth_attacks", concurrency=max(1, min(req.concurrency or 16, 32)),
        auth_cookie=req.auth_cookie, auth_bearer=req.auth_bearer,
        extra_body=None, jwt_token=jwt_token)
    return StreamingResponse(generator, media_type="application/x-ndjson",
        headers={"X-Accel-Buffering":"no", "Cache-Control":"no-store, no-transform",
                 "Connection":"keep-alive"})


@router.get("/api/auth_attacks/run_all/tiers")
async def auth_attacks_run_all_tiers():
    return {"tiers":[{"id":k,"tools":[n for n,_ in t],"count":len(t)}
                     for k,t in AUTH_ATTACKS_TOOLS_BY_TIER.items()],
            "total_tools": sum(len(t) for t in AUTH_ATTACKS_TOOLS_BY_TIER.values())}


def register(app):
    app.include_router(router)
