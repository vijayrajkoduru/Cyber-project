"""llm_ops_exposure - exposed LLM gateway + observability plane detection
(playbook §9 #103 LLM gateway audit — LiteLLM/Portkey, and §9 #105 LLM
observability platform info leak — Langfuse/Helicone/Phoenix/Ray).

REAL PROBE. Issues only READ-ONLY HTTP GET requests against the well-known
unauthenticated health/info/dashboard paths these platforms expose. A
graded finding is emitted ONLY when the platform's signature payload is
actually returned by the live target. We do NOT log in, do NOT POST, do
NOT submit model keys, and never chain the result anywhere.

What this catches in the real world:
  - A LiteLLM proxy whose /health or /model/info is reachable unauthenticated
  - A Langfuse / Helicone / Phoenix tracing UI exposed to the internet
  - A Ray dashboard reachable (already partially covered by serving FP; here
    we focus on the observability/job control surface)

Customer input:
  - ScanRequest.target = gateway/observability host[:port] or URL
"""
from __future__ import annotations
import asyncio
from typing import Optional
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools.ai_llm.tier3_infra._infra_common import (
    base_variants, build_headers, safe_join, body_excerpt,
)

router = APIRouter()


class InfraRequest(ScanRequest):
    options: Optional[dict] = None


# severity: "gateway_info" leaks model/route config (HIGH-ish), "dashboard"
# is an exposed UI (MEDIUM), "health" alone is low-signal INFO (we still note
# it but never grade it as a vuln on its own).
OPS_SIGNATURES = [
    {"platform": "LiteLLM proxy (model info)", "path": "/model/info",
     "body_any": ["\"model_name\"", "litellm_params", "model_info"],
     "must_status": [200], "class": "gateway_info"},
    {"platform": "LiteLLM proxy (health)", "path": "/health/liveliness",
     "body_any": ["i'm alive", "alive"], "must_status": [200],
     "class": "health"},
    {"platform": "LiteLLM proxy (v1 model list)", "path": "/v1/models",
     "body_any": ["\"object\": \"list\"", "litellm"], "must_status": [200],
     "class": "gateway_info"},
    {"platform": "Portkey gateway", "path": "/v1/health",
     "body_any": ["portkey", "\"ok\""], "must_status": [200],
     "class": "health"},
    {"platform": "Langfuse (health)", "path": "/api/public/health",
     "body_any": ["\"status\"", "\"version\""], "must_status": [200],
     "class": "dashboard"},
    {"platform": "Langfuse (UI)", "path": "/",
     "body_any": ["langfuse"], "must_status": [200], "class": "dashboard"},
    {"platform": "Helicone (UI)", "path": "/",
     "body_any": ["helicone"], "must_status": [200], "class": "dashboard"},
    {"platform": "Arize Phoenix (trace UI)", "path": "/",
     "body_any": ["phoenix", "arize"], "must_status": [200],
     "class": "dashboard"},
    {"platform": "Arize Phoenix (version)", "path": "/arize_phoenix_version",
     "body_any": ["arize", "phoenix"], "must_status": [200],
     "class": "dashboard", "weak": True},
    {"platform": "Arize Phoenix (GraphQL)", "path": "/graphql",
     "body_any": ["__schema", "\"data\"", "graphql"], "must_status": [200],
     "class": "dashboard", "weak": True},
    {"platform": "Ray dashboard (jobs API)", "path": "/api/jobs/",
     "body_any": ["job_id", "\"jobs\"", "submission_id"], "must_status": [200],
     "class": "gateway_info"},
    {"platform": "Flowise (LLM low-code)", "path": "/api/v1/ping",
     "body_any": ["pong"], "must_status": [200], "class": "health"},
    {"platform": "OpenWebUI", "path": "/health",
     "body_any": ["true", "\"status\""], "must_status": [200],
     "class": "dashboard", "weak": True},
]


async def gather(ctx: ScanContext):
    target = (ctx.host or "").strip()
    if not target:
        ctx.state["llmops_total"] = 0
        ctx.source("no-target")
        return
    try:
        import httpx
    except ImportError:
        ctx.state["llmops_error"] = "httpx not installed"
        ctx.source("httpx missing")
        return

    bases = base_variants(target)
    if not bases:
        ctx.state["llmops_error"] = "could not parse target into a base URL"
        ctx.source("invalid target")
        return

    opts = getattr(ctx, "options", None) or {}
    bearer = getattr(ctx, "auth_bearer", None)
    headers = build_headers(bearer, opts.get("headers"),
                            "VulnusLab/AI-LLM-Ops-Exposure")

    detected = []
    paths_probed = 0
    transport_errors = 0
    seen = set()

    async with httpx.AsyncClient(timeout=8.0, verify=False,
                                 follow_redirects=True) as client:
        sem = asyncio.Semaphore(4)

        async def _probe(base, sig):
            nonlocal paths_probed, transport_errors
            url = safe_join(base, sig["path"])
            async with sem:
                try:
                    r = await client.get(url, headers=headers)
                except Exception:
                    transport_errors += 1
                    return
            paths_probed += 1
            if r.status_code not in sig.get("must_status", [200]):
                return
            try:
                body = r.text or ""
            except Exception:
                body = ""
            low = body.lower()
            # Service-specific markers only — never an always-true catch-all.
            # A reachable-but-unsignatured endpoint is NOT a detection.
            body_any = [m for m in sig["body_any"] if m and m.strip(". ")]
            matched = any(m.lower() in low for m in body_any)
            if not matched:
                return
            if sig["platform"] in seen:
                return
            seen.add(sig["platform"])
            detected.append({
                "platform": sig["platform"],
                "url": url,
                "status": r.status_code,
                "class": sig.get("class"),
                "weak": bool(sig.get("weak")),
                "server_header": r.headers.get("server", ""),
                "excerpt": body_excerpt(body, 200),
            })

        tasks = []
        for base in bases:
            for sig in OPS_SIGNATURES:
                tasks.append(_probe(base, sig))
        await asyncio.gather(*tasks)

    ctx.state["llmops_bases"] = bases
    ctx.state["llmops_paths_probed"] = paths_probed
    ctx.state["llmops_transport_errors"] = transport_errors
    ctx.state["llmops_detected"] = detected
    ctx.state["llmops_total"] = len(detected)
    ctx.source(f"{paths_probed} read-only GETs; {len(detected)} LLM "
               f"gateway/observability surface(s) detected; "
               f"{transport_errors} transport errors")


def rule_unreachable(s):
    if s.get("llmops_error"):
        return {"name": "LLM gateway/observability exposure scan could not run",
                "severity": "INFO",
                "evidence": str(s["llmops_error"]),
                "remediation": ("Confirm the target is reachable. This probe "
                                "issues only read-only GETs to gateway/observability "
                                "health + info endpoints."),
                "cwe": "CWE-755"}
    return None


def rule_positive(s):
    if s.get("llmops_total", 0) > 0:
        return None
    if not s.get("llmops_paths_probed"):
        return None
    return {"name": "No exposed LLM gateway / observability plane detected",
            "severity": "POSITIVE",
            "evidence": (f"Probed {s.get('llmops_paths_probed', 0)} LiteLLM/"
                         "Portkey/Langfuse/Helicone/Phoenix/Ray/Flowise endpoints "
                         "— none responded with a platform signature."),
            "remediation": ("Keep LLM gateways and tracing dashboards behind "
                            "SSO/auth and private networking."),
            "cwe": "CWE-200", "owasp": "LLM10:2025"}


def rule_gateway_info_exposed(s):
    det = [d for d in (s.get("llmops_detected") or [])
           if d.get("class") == "gateway_info"]
    if not det:
        return None
    return {"name": (f"Unauthenticated LLM gateway info/route plane exposed "
                     f"({len(det)} endpoint(s))"),
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-200", "owasp": "LLM10:2025",
            "verified_exploit": True,
            "evidence": ("Gateway model/route config returned without auth: "
                         + "; ".join(f"{d['platform']} @ {d['url']}"
                                     for d in det[:5])),
            "remediation": ("Require a master key / virtual key on the gateway "
                            "(LiteLLM LITELLM_MASTER_KEY, Portkey API key) and "
                            "restrict /model/info, /v1/models, and Ray jobs API "
                            "to authenticated callers. Exposed route config "
                            "reveals upstream provider keys' usage + enables "
                            "cost-abuse and model enumeration.")}


def rule_dashboard_exposed(s):
    det = [d for d in (s.get("llmops_detected") or [])
           if d.get("class") == "dashboard"]
    if not det:
        return None
    strong = [d for d in det if not d.get("weak")]
    if strong:
        # Body-confirmed dashboard signature (langfuse/helicone/phoenix/etc.).
        return {"name": (f"Exposed LLM observability/dashboard UI "
                         f"({len(strong)} platform(s))"),
                "severity": "MEDIUM", "cvss": "5.3",
                "cwe": "CWE-200", "owasp": "LLM10:2025",
                "verified_exploit": True,
                "evidence": ("Observability surface reachable: "
                             + "; ".join(f"{d['platform']} @ {d['url']}"
                                         for d in strong[:5])),
                "remediation": ("Put Langfuse/Helicone/Phoenix tracing behind "
                                "SSO. Trace UIs can leak full prompt/response "
                                "history, user identifiers, and system prompts "
                                "— a sensitive information disclosure "
                                "(OWASP LLM02).")}
    # Only weak catch-all matches: endpoint reachable but dashboard NOT confirmed.
    weak = [d for d in det if d.get("weak")]
    return {"name": (f"LLM dashboard path reachable, presence not confirmed "
                     f"({len(weak)} endpoint(s))"),
            "severity": "INFO", "cvss": "0.0",
            "cwe": "CWE-200", "owasp": "LLM10:2025",
            "verified_exploit": False,
            "evidence": ("Endpoint responds but dashboard presence NOT "
                         "confirmed (weak catch-all signature only): "
                         + "; ".join(f"{d['platform']} @ {d['url']}"
                                     for d in weak[:5])),
            "remediation": ("Manually confirm whether an observability/trace UI "
                            "is served here. If so, put Langfuse/Helicone/"
                            "Phoenix tracing behind SSO — trace UIs can leak "
                            "prompt/response history and system prompts "
                            "(OWASP LLM02).")}


LLM_OPS_EXPOSURE_FINDING_RULES = [
    rule_unreachable,
    rule_positive,
    rule_gateway_info_exposed,
    rule_dashboard_exposed,
]


INTEL_FIELDS = [
    ("Base URLs probed", "llmops_bases"),
    ("Read-only GETs sent", "llmops_paths_probed"),
    ("Surfaces detected", "llmops_total"),
    ("Detected platforms", "llmops_detected"),
    ("Transport errors", "llmops_transport_errors"),
]


@router.post("/api/ai_llm/llm_ops_exposure")
async def ai_llm_llm_ops_exposure(req: InfraRequest,
                                  _=Depends(verify_scan_quota)):
    async def _gather(ctx):
        ctx.options = req.options
        ctx.auth_bearer = req.auth_bearer
        await gather(ctx)
    return await run_scanner(host=req.target, tool="llm_ops_exposure",
        gather_func=_gather, finding_rules=LLM_OPS_EXPOSURE_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
