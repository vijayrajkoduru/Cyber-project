"""mobile_aiml module orchestrator - §15 AI/ML IN APP (emerging 2025+)."""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_parallel, run_module_streaming

router = APIRouter()


MOBILE_AIML_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_model_security": [
        ("coreml_extraction_audit",       "/api/mobile_aiml/coreml_extraction_audit"),
        ("tflite_extraction_audit",       "/api/mobile_aiml/tflite_extraction_audit"),
        ("ondevice_llm_audit",            "/api/mobile_aiml/ondevice_llm_audit"),
        ("prompt_injection_in_app_audit", "/api/mobile_aiml/prompt_injection_in_app_audit"),
    ],
}


def _all_tools():
    out = []
    for tier in MOBILE_AIML_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class MobileAimlRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 4
    options: Optional[dict] = None


def _resolve(req, request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in MOBILE_AIML_TOOLS_BY_TIER:
                tools.extend(MOBILE_AIML_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    return tools, (req.options or {}), jwt


@router.post("/api/mobile_aiml/run_all")
async def mobile_aiml_run_all(req: MobileAimlRunAllRequest, request: Request,
                                _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 4, 8))
    gen = run_module_streaming(target=req.target, tools=tools, module_name="mobile_aiml",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt)
    return StreamingResponse(gen, media_type="application/x-ndjson",
        headers={"X-Accel-Buffering": "no",
                  "Cache-Control": "no-store, no-transform",
                  "Connection": "keep-alive"})


@router.post("/api/mobile_aiml/run_all_buffered")
async def mobile_aiml_run_all_buffered(req: MobileAimlRunAllRequest, request: Request,
                                         _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 4, 8))
    return await run_module_parallel(target=req.target, tools=tools, module_name="mobile_aiml",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt)


@router.get("/api/mobile_aiml/run_all/tiers")
async def mobile_aiml_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in MOBILE_AIML_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in MOBILE_AIML_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
