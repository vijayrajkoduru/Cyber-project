"""AI/LLM module orchestrator — 23_ai_llm.md (87 endpoints)."""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_streaming
from tools.ai_llm.ai_llm_pack import T as TECHNIQUES

router = APIRouter()

_RANGES = [
    ("tier1_owasp_llm_top10",  0, 12),
    ("tier2_prompt_injection", 12, 26),
    ("tier3_jailbreak",        26, 36),
    ("tier4_data_extraction",  36, 45),
    ("tier5_model_theft",      45, 50),
    ("tier6_rag_vector_db",    50, 57),
    ("tier7_agent_tool_use",   57, 66),
    ("tier8_supply_chain",     66, 75),
    ("tier9_infrastructure",   75, 86),
    ("tier10_compliance",      86, 87),  # collapsed
]

AI_LLM_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    k: [(t[0], f"/api/ai_llm/{t[0]}") for t in TECHNIQUES[a:b]]
    for k, a, b in _RANGES
}


class AILLMRunAllRequest(BaseModel):
    target: str
    concurrency: Optional[int] = 16
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None


def _all_tools():
    out = []
    for tools in AI_LLM_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


@router.post("/api/ai_llm/run_all")
async def ai_llm_run_all(req: AILLMRunAllRequest, request: Request,
                          _=Depends(verify_scan_quota)):
    jwt_token = request.headers.get("authorization", "").replace("Bearer ", "") or None
    return StreamingResponse(
        run_module_streaming(target=req.target, tools=_all_tools(),
            module_name="ai_llm", concurrency=max(1, min(req.concurrency or 16, 32)),
            auth_cookie=req.auth_cookie, auth_bearer=req.auth_bearer,
            extra_body=None, jwt_token=jwt_token),
        media_type="application/x-ndjson",
        headers={"X-Accel-Buffering":"no", "Cache-Control":"no-store, no-transform",
                 "Connection":"keep-alive"})


@router.get("/api/ai_llm/run_all/tiers")
async def ai_llm_run_all_tiers():
    return {"tiers":[{"id":k,"tools":[n for n,_ in t],"count":len(t)}
                     for k,t in AI_LLM_TOOLS_BY_TIER.items()],
            "total_tools": sum(len(t) for t in AI_LLM_TOOLS_BY_TIER.values())}


def register(app):
    app.include_router(router)
