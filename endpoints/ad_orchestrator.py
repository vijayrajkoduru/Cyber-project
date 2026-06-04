"""ad module orchestrator - Active Directory attacks.

Per module_playbooks/19_ad.md - 11 sections, 132 techniques.
Starter set (5 scanners, no-creds + AD CS) covers:
  - §1 Discovery: ldap_anon_enum, smb_signing_check, dc_discovery, enum4linux_ng_audit
  - §6 AD CS: certipy_find
More scanners will be added per playbook section in subsequent commits.
"""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_parallel, run_module_streaming

router = APIRouter()


AD_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_discovery": [
        ("ldap_anon_enum",         "/api/ad/ldap_anon_enum"),
        ("smb_signing_check",      "/api/ad/smb_signing_check"),
        ("dc_discovery",           "/api/ad/dc_discovery"),
        ("enum4linux_ng_audit",    "/api/ad/enum4linux_ng_audit"),
    ],
    "tier6_adcs": [
        ("certipy_find",           "/api/ad/certipy_find"),
    ],
}


def _all_tools():
    out = []
    for tier in AD_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class AdRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 4
    options: Optional[dict] = None


def _resolve(req, request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in AD_TOOLS_BY_TIER:
                tools.extend(AD_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    return tools, (req.options or {}), jwt


@router.post("/api/ad/run_all")
async def ad_run_all(req: AdRunAllRequest, request: Request,
                       _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 4, 8))
    gen = run_module_streaming(target=req.target, tools=tools, module_name="ad",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt)
    return StreamingResponse(gen, media_type="application/x-ndjson",
        headers={"X-Accel-Buffering": "no",
                  "Cache-Control": "no-store, no-transform",
                  "Connection": "keep-alive"})


@router.post("/api/ad/run_all_buffered")
async def ad_run_all_buffered(req: AdRunAllRequest, request: Request,
                                _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 4, 8))
    return await run_module_parallel(target=req.target, tools=tools, module_name="ad",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt)


@router.get("/api/ad/run_all/tiers")
async def ad_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in AD_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in AD_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
