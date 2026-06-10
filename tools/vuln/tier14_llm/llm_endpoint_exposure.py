"""Exposed LLM / chat-completion endpoint detection. VL-FORGE Vuln tier14 - §14 (LLM attack surface).

VL-VERIFY: SPA bundles routinely contain LLM marker words ('messages',
'completion', 'prompt', 'temperature', 'openai', 'anthropic') because
they ship chat-UI widgets, docs, or marketing copy. The SPA catch-all
returns the same bundle for every probed path, so any path whose marker
count came from the SPA shell is a FP. We drop those.
"""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._vl_core import run_scanner
from tools.vuln._vuln_common import http_get, detect_spa_catchall, is_same_as_canary

router = APIRouter()
_PATHS = ["/v1/chat/completions", "/api/chat", "/chat", "/v1/completions", "/api/completions",
          "/api/generate", "/api/llm", "/openai/v1/chat/completions", "/api/ai", "/assistant"]
_MARK = ["messages", "max_tokens", "completion", "choices", "model required", "prompt",
         "temperature", "openai", "anthropic"]


async def gather(ctx):
    base = web_url(str(ctx.host)).rstrip("/")
    spa = await detect_spa_catchall(base)
    ctx.state["spa_catchall"] = spa.get("is_spa", False)
    canary_body = spa.get("canary_body", "") or ""

    async def _c(p):
        r = await asyncio.to_thread(http_get, base + p, 8, 4000)
        if not r or r.get("status") == 404:
            return None
        b = (r.get("body", "") or "")
        # SPA suppression: if response IS the SPA shell, marker count came
        # from bundle - not a real LLM endpoint.
        if spa.get("is_spa") and is_same_as_canary(b, canary_body):
            return ("__spa_suppressed__", p)
        if sum(1 for m in _MARK if m in b.lower()) >= 2:
            return (p, r.get("status"))
        return None

    res = await asyncio.gather(*[_c(p) for p in _PATHS])
    ctx.source("http")
    ctx.state["tested"] = len(_PATHS)
    found = []
    suppressed = []
    for item in res:
        if not item: continue
        if item[0] == "__spa_suppressed__":
            suppressed.append(item[1])
        else:
            found.append(f"{item[0]} ({item[1]})")
    if found:
        ctx.state["llm_endpoints"] = found
    if suppressed:
        ctx.state["spa_suppressed_endpoints"] = suppressed


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
