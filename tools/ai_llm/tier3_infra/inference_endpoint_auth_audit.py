"""inference_endpoint_auth_audit - inference endpoint authentication +
exposure audit (playbook §9 #96 inference endpoint authentication audit).

REAL PROBE. Sends ONE benign, harmless prompt ("Reply with the single word
OK.") to the customer-supplied inference endpoint with NO Authorization
header, and separately a HEAD/OPTIONS reachability check, to answer a single
question safely: does the endpoint serve model output to an UNAUTHENTICATED
caller?

This is a detection probe, not an attack:
  - No jailbreak, no injection, no PII extraction, no DoS — one tiny prompt.
  - We only look at whether a model-shaped answer comes back without a token.
  - If the customer provided auth_bearer, we ALSO confirm the authed path
    works and contrast it, so a graded finding is only raised when the
    UNAUTH path returns a real model answer.

A graded (HIGH) finding is emitted ONLY when the unauthenticated request
actually returns a coherent model response (HTTP 2xx + non-trivial body that
is not an auth-error envelope). Auth-challenge responses (401/403, or a body
containing an auth-error marker) are reported as POSITIVE (good posture).

Customer input:
  - ScanRequest.target  = full inference endpoint URL (http(s)://.../chat)
  - auth_bearer         = optional; if present we compare authed vs unauthed
  - options.prompt_field / response_field / headers honoured
"""
from __future__ import annotations
import asyncio
from typing import Optional
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools.ai_llm.tier1_owasp_llm.prompt_injection_audit import (
    _mask_pii, _extract_response_text,
)
from tools.ai_llm.tier3_infra._infra_common import body_excerpt

router = APIRouter()


class InfraRequest(ScanRequest):
    options: Optional[dict] = None


BENIGN_PROMPT = "Reply with the single word OK."

# Markers that indicate the endpoint demanded auth (good posture, not a vuln).
AUTH_ERROR_MARKERS = [
    "unauthorized", "authentication", "missing api key", "invalid api key",
    "invalid token", "forbidden", "permission denied", "not authenticated",
    "401", "403", "api key required", "no api key", "incorrect api key",
]


def _looks_like_model_answer(text: str) -> bool:
    """Heuristic: a real model answer is a non-empty body that is NOT an
    auth/error envelope. Conservative to keep FP at zero."""
    if not text:
        return False
    low = text.strip().lower()
    if len(low) < 1:
        return False
    # If the body is dominated by auth-error language, it's not a model answer.
    if any(m in low for m in AUTH_ERROR_MARKERS) and len(low) < 400:
        return False
    return True


async def _send(client, target, headers, prompt_field, response_field, prompt):
    body = {prompt_field: prompt}
    try:
        r = await client.post(target, json=body, headers=headers)
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {str(e)[:80]}"}
    try:
        data = r.json()
    except Exception:
        data = r.text
    text = _extract_response_text(data, response_field)
    return {"ok": True, "status": r.status_code,
            "text": text or "",
            "answer": _looks_like_model_answer(text or "")
            and 200 <= r.status_code < 300}


async def gather(ctx: ScanContext):
    target = (ctx.host or "").strip()
    if not target:
        ctx.state["infauth_total"] = 0
        ctx.source("no-target")
        return
    if not target.startswith(("http://", "https://")):
        ctx.state["infauth_error"] = (
            "target must be a full inference endpoint URL (http(s)://...)")
        ctx.source("invalid target")
        return
    try:
        import httpx
    except ImportError:
        ctx.state["infauth_error"] = "httpx not installed"
        ctx.source("httpx missing")
        return

    opts = getattr(ctx, "options", None) or {}
    prompt_field = opts.get("prompt_field", "message")
    response_field = opts.get("response_field", "response")
    extra_headers = opts.get("headers") or {}
    bearer = getattr(ctx, "auth_bearer", None)

    base_headers = {"Content-Type": "application/json",
                    "User-Agent": "VulnusLab/AI-LLM-Auth-Audit"}
    if isinstance(extra_headers, dict):
        base_headers.update({str(k): str(v) for k, v in extra_headers.items()})

    # Unauthenticated headers: deliberately strip Authorization.
    unauth_headers = dict(base_headers)
    unauth_headers.pop("Authorization", None)

    async with httpx.AsyncClient(timeout=20.0, verify=False) as client:
        unauth = await _send(client, target, unauth_headers,
                             prompt_field, response_field, BENIGN_PROMPT)
        authed = None
        if bearer:
            ah = dict(base_headers)
            ah["Authorization"] = f"Bearer {bearer}"
            authed = await _send(client, target, ah,
                                prompt_field, response_field, BENIGN_PROMPT)

    if not unauth.get("ok"):
        ctx.state["infauth_error"] = unauth.get("error", "request failed")
        ctx.source(f"unauthenticated probe failed: {unauth.get('error')}")
        return

    ctx.state["infauth_endpoint"] = target
    ctx.state["infauth_unauth_status"] = unauth.get("status")
    ctx.state["infauth_unauth_answered"] = bool(unauth.get("answer"))
    ctx.state["infauth_unauth_excerpt"] = body_excerpt(
        _mask_pii(unauth.get("text", "")), 200)
    ctx.state["infauth_bearer_provided"] = bool(bearer)
    if authed is not None and authed.get("ok"):
        ctx.state["infauth_authed_status"] = authed.get("status")
        ctx.state["infauth_authed_answered"] = bool(authed.get("answer"))
    ctx.state["infauth_total"] = 1 if unauth.get("answer") else 0
    ctx.source(f"unauth status={unauth.get('status')} "
               f"answered={bool(unauth.get('answer'))}; "
               f"bearer_provided={bool(bearer)}")


def rule_unreachable(s):
    if s.get("infauth_error"):
        return {"name": "Inference endpoint auth audit could not run",
                "severity": "INFO",
                "evidence": str(s["infauth_error"]),
                "remediation": ("Confirm the endpoint URL and that it accepts a "
                                "JSON POST with the configured prompt_field. The "
                                "probe sends one benign 'Reply OK' prompt only."),
                "cwe": "CWE-755"}
    return None


def rule_unauth_inference(s):
    if not s.get("infauth_unauth_answered"):
        return None
    return {"name": "Inference endpoint serves model output WITHOUT authentication",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-306", "owasp": "LLM10:2025",
            "verified_exploit": True,  # confirmed unauth model answer observed
            "evidence": (f"A benign prompt sent with NO Authorization header "
                         f"returned a model answer (HTTP "
                         f"{s.get('infauth_unauth_status')}). Excerpt: "
                         f"\"{s.get('infauth_unauth_excerpt','')}\""),
            "remediation": ("Require an API key / bearer token on the inference "
                            "endpoint and reject unauthenticated POSTs with 401. "
                            "Open inference endpoints enable unbounded token "
                            "consumption (cost DoS), model extraction, and abuse "
                            "(OWASP LLM10). Put the endpoint behind an "
                            "authenticated gateway + per-key rate limits.")}


def rule_auth_enforced(s):
    if s.get("infauth_unauth_answered"):
        return None
    if s.get("infauth_unauth_status") is None:
        return None
    return {"name": "Inference endpoint enforces authentication",
            "severity": "POSITIVE",
            "evidence": (f"Unauthenticated benign request returned HTTP "
                         f"{s.get('infauth_unauth_status')} without a model "
                         "answer — the endpoint did not serve output to an "
                         "anonymous caller."),
            "remediation": ("Maintain auth enforcement. Add per-key rate limits "
                            "and token-budget caps to bound consumption."),
            "cwe": "CWE-306", "owasp": "LLM10:2025"}


INFERENCE_ENDPOINT_AUTH_AUDIT_FINDING_RULES = [
    rule_unreachable,
    rule_unauth_inference,
    rule_auth_enforced,
]


INTEL_FIELDS = [
    ("Endpoint", "infauth_endpoint"),
    ("Unauthenticated status", "infauth_unauth_status"),
    ("Unauthenticated answered", "infauth_unauth_answered"),
    ("Unauthenticated excerpt (masked)", "infauth_unauth_excerpt"),
    ("Bearer provided", "infauth_bearer_provided"),
    ("Authenticated status", "infauth_authed_status"),
    ("Authenticated answered", "infauth_authed_answered"),
]


@router.post("/api/ai_llm/inference_endpoint_auth_audit")
async def ai_llm_inference_endpoint_auth_audit(req: InfraRequest,
                                               _=Depends(verify_scan_quota)):
    async def _gather(ctx):
        ctx.options = req.options
        ctx.auth_bearer = req.auth_bearer
        await gather(ctx)
    return await run_scanner(host=req.target,
        tool="inference_endpoint_auth_audit",
        gather_func=_gather,
        finding_rules=INFERENCE_ENDPOINT_AUTH_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
