"""Phishing module orchestrator — 26_phishing.md (70 endpoints)."""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_streaming
from tools.phishing.phishing_pack import TECHNIQUES

router = APIRouter()

_SECTION_RANGES = [
    ("tier1_email_phishing",   0, 14),
    ("tier2_site_cloning",     14, 22),
    ("tier3_aitm",             22, 32),
    ("tier4_smish_vish_quish", 32, 42),
    ("tier5_oauth_consent",    42, 50),
    ("tier6_deepfake_ai",      50, 60),
    ("tier7_campaign_mgmt",    60, 70),
]

PHISHING_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    tier_id: [(t[0], f"/api/phishing/{t[0]}") for t in TECHNIQUES[a:b]]
    for tier_id, a, b in _SECTION_RANGES
}


class PhishingRunAllRequest(BaseModel):
    target: str
    concurrency: Optional[int] = 16
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None


def _all_tools():
    out = []
    for tools in PHISHING_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


@router.post("/api/phishing/run_all")
async def phishing_run_all(req: PhishingRunAllRequest, request: Request,
                            _=Depends(verify_scan_quota)):
    jwt_token = request.headers.get("authorization", "").replace("Bearer ", "") or None
    generator = run_module_streaming(target=req.target, tools=_all_tools(),
        module_name="phishing", concurrency=max(1, min(req.concurrency or 16, 32)),
        auth_cookie=req.auth_cookie, auth_bearer=req.auth_bearer,
        extra_body=None, jwt_token=jwt_token)
    return StreamingResponse(generator, media_type="application/x-ndjson",
        headers={"X-Accel-Buffering":"no", "Cache-Control":"no-store, no-transform",
                 "Connection":"keep-alive"})


@router.get("/api/phishing/run_all/tiers")
async def phishing_run_all_tiers():
    return {"tiers":[{"id":k,"tools":[n for n,_ in t],"count":len(t)}
                     for k,t in PHISHING_TOOLS_BY_TIER.items()],
            "total_tools": sum(len(t) for t in PHISHING_TOOLS_BY_TIER.values())}


def register(app):
    app.include_router(router)
