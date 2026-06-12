"""ai_llm module orchestrator - OWASP LLM Top 10 (2025) security testing.

Per module_playbooks/23_ai_llm.md - 10 sections, 114 techniques.

Live-probe + advisory coverage:
  - tier1_owasp_llm (active prompt-level probes):
      * prompt_injection_audit  (LLM01)
      * jailbreak_resistance_test (LLM02)
      * pii_leak_test  (LLM06)
  - tier2_defenses (defensive baseline):
      * llm_guard_input_scan  (open-source input guardrails P/R/F1)
      * garak_owasp_test_suite (Garak DAN-11 / Base64 / GTPhish probes)
  - tier3_infra (REAL read-only remote exposure probes — §6 #68, §9):
      * model_serving_fingerprint      (vLLM/TGI/Triton/Ollama/Ray FP)
      * vector_db_exposure             (unauth Chroma/Qdrant/Weaviate/Milvus)
      * llm_ops_exposure               (LiteLLM/Portkey gateways + Langfuse/
                                        Helicone/Phoenix observability)
      * inference_endpoint_auth_audit  (unauthenticated inference serving)
      * llm_output_handling_headers    (LLM05 XSS-via-LLM + CORS/transport)
  - tier4_advisory (honest advisory-by-design — §4 #48-49, §5, §7, §8, §10,
    multi-modal/white-box, manual red-team):
      * ai_redteam_advisory            (INFO-only, vulnerable:false)

Severity discipline: every tier3 graded finding is emitted ONLY when the
condition was actually observed on the live target. Everything advisory or
undetected is INFO. Concurrency defaulted to 2 because production LLM
endpoints rate-limit aggressively.
"""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_parallel, run_module_streaming

router = APIRouter()


AI_LLM_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_owasp_llm": [
        ("prompt_injection_audit",     "/api/ai_llm/prompt_injection_audit"),
        ("jailbreak_resistance_test",  "/api/ai_llm/jailbreak_resistance_test"),
        ("pii_leak_test",              "/api/ai_llm/pii_leak_test"),
    ],
    "tier2_defenses": [
        ("llm_guard_input_scan",       "/api/ai_llm/llm_guard_input_scan"),
        ("garak_owasp_test_suite",     "/api/ai_llm/garak_owasp_test_suite"),
    ],
    # tier3_infra — REAL read-only remote exposure probes against the LLM
    # endpoint/host. Each emits a graded finding ONLY when the condition is
    # actually observed on the live target (zero false positives).
    "tier3_infra": [
        ("model_serving_fingerprint",      "/api/ai_llm/model_serving_fingerprint"),
        ("vector_db_exposure",             "/api/ai_llm/vector_db_exposure"),
        ("llm_ops_exposure",               "/api/ai_llm/llm_ops_exposure"),
        ("inference_endpoint_auth_audit",  "/api/ai_llm/inference_endpoint_auth_audit"),
        ("llm_output_handling_headers",    "/api/ai_llm/llm_output_handling_headers"),
    ],
    # tier4_advisory — honest advisory-by-design coverage for playbook
    # techniques that cannot be detected from an external SaaS scanner
    # (model theft, supply-chain artifacts, agent toolchain, white-box /
    # multi-modal, compliance, manual red-team). All INFO, vulnerable:false.
    "tier4_advisory": [
        ("ai_redteam_advisory",        "/api/ai_llm/ai_redteam_advisory"),
    ],
}


def _all_tools():
    out = []
    for tier in AI_LLM_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class AiLlmRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    # LLM endpoints rate-limit aggressively — default fan-out concurrency 2.
    concurrency: Optional[int] = 2
    # Customer's LLM endpoint auth (forwarded to every scanner)
    auth_bearer: Optional[str] = None
    # Per-tool body extras — typically {"prompt_field": "...",
    # "response_field": "...", "headers": {...}}.
    options: Optional[dict] = None


def _resolve(req: AiLlmRunAllRequest, request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in AI_LLM_TOOLS_BY_TIER:
                tools.extend(AI_LLM_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    extra = {}
    if req.options:
        # Pack into per-tool body as `options` since our scanners read
        # it off req.options (PromptInjectionRequest carries .options).
        extra["options"] = req.options
    return tools, extra or None, jwt


@router.post("/api/ai_llm/run_all")
async def ai_llm_run_all(req: AiLlmRunAllRequest, request: Request,
                          _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 2, 4))
    gen = run_module_streaming(target=req.target, tools=tools,
        module_name="ai_llm", concurrency=concurrency,
        auth_bearer=req.auth_bearer, extra_body=extra, jwt_token=jwt)
    return StreamingResponse(gen, media_type="application/x-ndjson",
        headers={"X-Accel-Buffering": "no",
                  "Cache-Control": "no-store, no-transform",
                  "Connection": "keep-alive"})


@router.post("/api/ai_llm/run_all_buffered")
async def ai_llm_run_all_buffered(req: AiLlmRunAllRequest, request: Request,
                                     _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 2, 4))
    return await run_module_parallel(target=req.target, tools=tools,
        module_name="ai_llm", concurrency=concurrency,
        auth_bearer=req.auth_bearer, extra_body=extra, jwt_token=jwt)


@router.get("/api/ai_llm/run_all/tiers")
async def ai_llm_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in AI_LLM_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in AI_LLM_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
