"""mobile_webview module orchestrator - §7 WEBVIEW."""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_parallel, run_module_streaming

router = APIRouter()


MOBILE_WEBVIEW_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_bridge": [
        ("addjavascriptinterface_audit", "/api/mobile_webview/addjavascriptinterface_audit"),
        ("hybrid_bridge_audit",          "/api/mobile_webview/hybrid_bridge_audit"),
        ("csp_trusted_types_audit",      "/api/mobile_webview/csp_trusted_types_audit"),
    ],
    "tier2_loading": [
        ("file_scheme_audit",           "/api/mobile_webview/file_scheme_audit"),
        ("override_url_loading_audit",  "/api/mobile_webview/override_url_loading_audit"),
        ("service_worker_audit",        "/api/mobile_webview/service_worker_audit"),
    ],
}


def _all_tools():
    out = []
    for tier in MOBILE_WEBVIEW_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class MobileWebviewRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 4
    options: Optional[dict] = None


def _resolve(req, request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in MOBILE_WEBVIEW_TOOLS_BY_TIER:
                tools.extend(MOBILE_WEBVIEW_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    return tools, (req.options or {}), jwt


@router.post("/api/mobile_webview/run_all")
async def mobile_webview_run_all(req: MobileWebviewRunAllRequest, request: Request,
                                   _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 4, 8))
    gen = run_module_streaming(target=req.target, tools=tools, module_name="mobile_webview",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt)
    return StreamingResponse(gen, media_type="application/x-ndjson",
        headers={"X-Accel-Buffering": "no",
                  "Cache-Control": "no-store, no-transform",
                  "Connection": "keep-alive"})


@router.post("/api/mobile_webview/run_all_buffered")
async def mobile_webview_run_all_buffered(req: MobileWebviewRunAllRequest, request: Request,
                                            _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 4, 8))
    return await run_module_parallel(target=req.target, tools=tools, module_name="mobile_webview",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt)


@router.get("/api/mobile_webview/run_all/tiers")
async def mobile_webview_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in MOBILE_WEBVIEW_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in MOBILE_WEBVIEW_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
