"""APISec module orchestrator — 22_apisec.md (108 endpoints)."""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_streaming
from tools.apisec.apisec_pack import T as TECHNIQUES

router = APIRouter()

_RANGES = [
    ("tier1_discovery",       0, 13),
    ("tier2_owasp_api",       13, 32),
    ("tier3_authentication",  32, 44),
    ("tier4_authorization",   44, 54),
    ("tier5_rate_limit",      54, 61),
    ("tier6_graphql",         61, 73),
    ("tier7_grpc",            73, 81),
    ("tier8_ws_sse",          81, 90),
    ("tier9_soap_rest_legacy", 90, 99),
    ("tier10_supply_versioning", 99, 108),
]

APISEC_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    k: [(t[0], f"/api/apisec/{t[0]}") for t in TECHNIQUES[a:b]]
    for k, a, b in _RANGES
}


class ApisecRunAllRequest(BaseModel):
    target: str
    concurrency: Optional[int] = 16
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None
    api_spec_url: Optional[str] = None


def _all_tools():
    out = []
    for tools in APISEC_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


@router.post("/api/apisec/run_all")
async def apisec_run_all(req: ApisecRunAllRequest, request: Request,
                          _=Depends(verify_scan_quota)):
    jwt_token = request.headers.get("authorization", "").replace("Bearer ", "") or None
    extra = {"api_spec_url": req.api_spec_url} if req.api_spec_url else None
    return StreamingResponse(
        run_module_streaming(target=req.target, tools=_all_tools(),
            module_name="apisec", concurrency=max(1, min(req.concurrency or 16, 32)),
            auth_cookie=req.auth_cookie, auth_bearer=req.auth_bearer,
            extra_body=extra, jwt_token=jwt_token),
        media_type="application/x-ndjson",
        headers={"X-Accel-Buffering":"no", "Cache-Control":"no-store, no-transform",
                 "Connection":"keep-alive"})


@router.get("/api/apisec/run_all/tiers")
async def apisec_run_all_tiers():
    return {"tiers":[{"id":k,"tools":[n for n,_ in t],"count":len(t)}
                     for k,t in APISEC_TOOLS_BY_TIER.items()],
            "total_tools": sum(len(t) for t in APISEC_TOOLS_BY_TIER.values())}


def register(app):
    app.include_router(router)
