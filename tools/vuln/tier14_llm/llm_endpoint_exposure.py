"""Exposed LLM / chat-completion endpoint detection. VL-FORGE Vuln tier14 - §14 (LLM attack surface)."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._framework import run_scanner
from tools.vuln._vuln_common import http_get

router = APIRouter()
_PATHS = ["/v1/chat/completions", "/api/chat", "/chat", "/v1/completions", "/api/completions",
          "/api/generate", "/api/llm", "/openai/v1/chat/completions", "/api/ai", "/assistant"]
_MARK = ["messages", "max_tokens", "completion", "choices", "model required", "prompt",
         "temperature", "openai", "anthropic"]


async def gather(ctx):
    base = web_url(str(ctx.host)).rstrip("/")

    async def _c(p):
        r = await asyncio.to_thread(http_get, base + p, 8, 4000)
        if not r or r.get("status") == 404:
            return None
        b = (r.get("body", "") or "").lower()
        if sum(1 for m in _MARK if m in b) >= 2:
            return (p, r.get("status"))
        return None

    res = await asyncio.gather(*[_c(p) for p in _PATHS])
    ctx.source("http")
    ctx.state["tested"] = len(_PATHS)
    found = []
    for item in res:
        if item:
            found.append(f"{item[0]} ({item[1]})")
    if found:
        ctx.state["llm_endpoints"] = found


def _r_llm(s):
    e = s.get("llm_endpoints") or []
    if not e:
        return None
    return {"name": f"Potential LLM/chat endpoint exposed ({len(e)})", "severity": "LOW", "cvss": 3.7,
            "cwe": "CWE-749",
            "evidence": f"LLM-API signatures at: {', '.join(e[:4])} - test for prompt injection / system-prompt leak",
            "remediation": "Auth-gate + rate-limit the LLM endpoint; run Garak/PyRIT; enforce output filtering + token budgets."}


def _r_clean(s):
    if (s.get("tested") or 0) < 1 or s.get("llm_endpoints"):
        return None
    return {"name": "No exposed LLM endpoint detected", "severity": "POSITIVE",
            "evidence": "No chat/completion API signatures on common paths."}


FINDING_RULES = [_r_llm, _r_clean]
INTEL_FIELDS = [("LLM endpoints", "llm_endpoints")]


@router.post("/api/vuln/llm_endpoint_exposure")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="llm_endpoint_exposure",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
