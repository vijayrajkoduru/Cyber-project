"""Cloud module orchestrator — 21_cloud.md (124 endpoints)."""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_streaming
from tools.cloud.cloud_pack import T as TECHNIQUES

router = APIRouter()

_RANGES = [
    ("tier1_discovery",       0, 14),
    ("tier2_aws",             14, 33),
    ("tier3_azure",           33, 48),
    ("tier4_gcp",             48, 60),
    ("tier5_ciem_multicloud", 60, 70),
    ("tier6_serverless",      70, 80),
    ("tier7_container_reg",   80, 89),
    ("tier8_storage",         89, 99),
    ("tier9_network_vpc",     99, 107),
    ("tier10_secrets_kms",    107, 115),
    ("tier11_oidc",           115, 121),
    ("tier12_compliance",     121, 125),
]

CLOUD_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    k: [(t[0], f"/api/cloud/{t[0]}") for t in TECHNIQUES[a:b]]
    for k, a, b in _RANGES
}


class CloudRunAllRequest(BaseModel):
    target: str
    concurrency: Optional[int] = 16
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None
    repo_url: Optional[str] = None


def _all_tools():
    out = []
    for tools in CLOUD_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


@router.post("/api/cloud/run_all")
async def cloud_run_all(req: CloudRunAllRequest, request: Request,
                         _=Depends(verify_scan_quota)):
    jwt_token = request.headers.get("authorization", "").replace("Bearer ", "") or None
    extra = {"repo_url": req.repo_url} if req.repo_url else None
    return StreamingResponse(
        run_module_streaming(target=req.target, tools=_all_tools(),
            module_name="cloud", concurrency=max(1, min(req.concurrency or 16, 32)),
            auth_cookie=req.auth_cookie, auth_bearer=req.auth_bearer,
            extra_body=extra, jwt_token=jwt_token),
        media_type="application/x-ndjson",
        headers={"X-Accel-Buffering":"no", "Cache-Control":"no-store, no-transform",
                 "Connection":"keep-alive"})


@router.get("/api/cloud/run_all/tiers")
async def cloud_run_all_tiers():
    return {"tiers":[{"id":k,"tools":[n for n,_ in t],"count":len(t)}
                     for k,t in CLOUD_TOOLS_BY_TIER.items()],
            "total_tools": sum(len(t) for t in CLOUD_TOOLS_BY_TIER.values())}


def register(app):
    app.include_router(router)
