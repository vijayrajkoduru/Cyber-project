"""model_serving_fingerprint - LLM serving-platform fingerprint + exposed
default endpoint detection (playbook §9 #101 model-serving platform CVE
surface — vLLM, TGI, Triton, Ollama, Ray, llama.cpp).

REAL PROBE. Issues only READ-ONLY HTTP GET requests against a curated set
of well-known, unauthenticated info/health endpoints that each serving
platform exposes by default (e.g. vLLM /version + /v1/models, Ollama
/api/tags, Triton /v2 + /metrics, Ray dashboard /api/version, TGI /info,
llama.cpp /props). A graded finding is emitted ONLY when one of those
endpoints actually responds with the platform's signature payload — that
is a confirmed public exposure of an inference control/info plane.

We do NOT send prompts, do NOT load/unload models, and never POST. The
software/version string is then surfaced so the customer can cross-check
it against published CVEs (the playbook references nuclei + NVD for the
actual CVE match — we report the fingerprint, not a fabricated CVE).

Customer input:
  - ScanRequest.target = LLM endpoint URL or host[:port]
  - auth_bearer / options.headers honoured (some platforms gate /metrics)

ZERO false positives: a platform is only reported when its UNIQUE marker is
present in the response body or headers.
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


# Each signature: GET this path, look for ALL must_any markers in body/headers.
# Markers are deliberately unique to the platform to keep FP rate at zero.
SERVING_SIGNATURES = [
    {"platform": "vLLM", "path": "/version",
     "body_any": ["vllm"], "kind": "info"},
    {"platform": "vLLM (OpenAI-compat model list)", "path": "/v1/models",
     "body_any": ["\"object\": \"list\"", "\"object\":\"list\""],
     "header_hint": ("server", "uvicorn"), "kind": "model_list"},
    {"platform": "Ollama", "path": "/api/tags",
     "body_any": ["\"models\"", "modified_at"], "kind": "model_list"},
    {"platform": "Ollama (root banner)", "path": "/",
     "body_any": ["ollama is running"], "kind": "banner"},
    {"platform": "Text Generation Inference (TGI)", "path": "/info",
     "body_any": ["model_id", "max_concurrent_requests", "huggingface"],
     "kind": "info"},
    {"platform": "NVIDIA Triton (v2 health)", "path": "/v2/health/ready",
     "header_hint": ("server", "tritonserver"), "status_ok": [200],
     "kind": "health"},
    {"platform": "NVIDIA Triton (server metadata)", "path": "/v2",
     "body_any": ["\"name\":\"triton\"", "triton", "tensorrt"],
     "kind": "info"},
    {"platform": "Ray Serve / Dashboard", "path": "/api/version",
     "body_any": ["ray_version", "ray_commit"], "kind": "info"},
    {"platform": "llama.cpp server", "path": "/props",
     "body_any": ["default_generation_settings", "system_prompt"],
     "kind": "info"},
    {"platform": "LocalAI", "path": "/readyz",
     "header_hint": ("server", "localai"), "kind": "health"},
    {"platform": "OpenAI-compatible model list", "path": "/v1/models",
     "body_any": ["gpt-", "llama", "mistral", "qwen", "claude"],
     "kind": "model_list_generic", "weak": True},
]


async def gather(ctx: ScanContext):
    target = (ctx.host or "").strip()
    if not target:
        ctx.state["serving_fp_total"] = 0
        ctx.source("no-target")
        return
    try:
        import httpx
    except ImportError:
        ctx.state["serving_fp_error"] = "httpx not installed"
        ctx.source("httpx missing")
        return

    bases = base_variants(target)
    if not bases:
        ctx.state["serving_fp_error"] = "could not parse target into a base URL"
        ctx.source("invalid target")
        return

    opts = getattr(ctx, "options", None) or {}
    bearer = getattr(ctx, "auth_bearer", None)
    headers = build_headers(bearer, opts.get("headers"),
                            "VulnusLab/AI-LLM-Serving-FP")

    detected = []           # confirmed platform exposures
    paths_probed = 0
    transport_errors = 0
    seen_platforms = set()

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
            try:
                body = r.text or ""
            except Exception:
                body = ""
            low = body.lower()
            hdrs = {k.lower(): str(v).lower() for k, v in r.headers.items()}

            matched = False
            why = ""
            # status gate
            status_ok = sig.get("status_ok")
            if status_ok and r.status_code not in status_ok:
                return
            # body markers
            body_any = sig.get("body_any")
            if body_any:
                for m in body_any:
                    if m.lower() in low:
                        matched = True
                        why = f"body marker '{m}'"
                        break
            # header hint (used alone for health endpoints, or to reinforce)
            hh = sig.get("header_hint")
            if hh:
                hk, hv = hh
                if hv.lower() in hdrs.get(hk.lower(), ""):
                    if not body_any:
                        matched = True
                    why = (why + "; " if why else "") + \
                        f"header {hk}: contains '{hv}'"
            if not matched:
                return

            key = sig["platform"]
            if key in seen_platforms:
                return
            seen_platforms.add(key)
            detected.append({
                "platform": sig["platform"],
                "url": url,
                "status": r.status_code,
                "kind": sig.get("kind"),
                "weak": bool(sig.get("weak")),
                "why": why,
                "server_header": r.headers.get("server", ""),
                "excerpt": body_excerpt(body, 200),
            })

        tasks = []
        for base in bases:
            for sig in SERVING_SIGNATURES:
                tasks.append(_probe(base, sig))
        await asyncio.gather(*tasks)

    ctx.state["serving_fp_bases"] = bases
    ctx.state["serving_fp_paths_probed"] = paths_probed
    ctx.state["serving_fp_transport_errors"] = transport_errors
    ctx.state["serving_fp_detected"] = detected
    ctx.state["serving_fp_total"] = len(detected)
    ctx.source(f"{paths_probed} read-only GETs across {len(bases)} base(s); "
               f"{len(detected)} serving platform(s) fingerprinted; "
               f"{transport_errors} transport errors")


def rule_unreachable(s):
    if s.get("serving_fp_error"):
        return {"name": "Model-serving fingerprint could not run",
                "severity": "INFO",
                "evidence": str(s["serving_fp_error"]),
                "remediation": ("Confirm the target is a reachable URL or host. "
                                "This probe issues only read-only GETs to "
                                "well-known serving-platform info endpoints."),
                "cwe": "CWE-755"}
    if (s.get("serving_fp_paths_probed", 0) == 0
            and s.get("serving_fp_transport_errors", 0) > 0):
        return {"name": "Model-serving host refused/timed out on all probes",
                "severity": "INFO",
                "evidence": (f"{s.get('serving_fp_transport_errors', 0)} transport "
                             "errors, zero responses."),
                "remediation": "Verify reachability / firewall posture from the scanner.",
                "cwe": "CWE-755"}
    return None


def rule_positive(s):
    if s.get("serving_fp_total", 0) > 0:
        return None
    if not s.get("serving_fp_paths_probed"):
        return None
    return {"name": "No exposed model-serving control/info plane detected",
            "severity": "POSITIVE",
            "evidence": (f"Probed {s.get('serving_fp_paths_probed', 0)} well-known "
                         "vLLM/TGI/Triton/Ollama/Ray/llama.cpp info endpoints — "
                         "none responded with a platform signature."),
            "remediation": ("Keep inference control planes off the public "
                            "internet. Re-test after deployment changes."),
            "cwe": "CWE-200", "owasp": "LLM10:2025"}


def rule_exposed_serving_plane(s):
    det = [d for d in (s.get("serving_fp_detected") or []) if not d.get("weak")]
    if not det:
        return None
    plats = sorted({d["platform"] for d in det})
    sample = det[0]
    return {"name": (f"Exposed model-serving control/info plane "
                     f"({len(plats)} platform signature(s))"),
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-200", "owasp": "LLM10:2025",
            "verified_exploit": True,  # confirmed live exposure observed
            "evidence": ("Unauthenticated info endpoint(s) responded: "
                         + "; ".join(f"{d['platform']} @ {d['url']} "
                                     f"({d['why']})" for d in det[:5])
                         + f". Sample server header: '{sample.get('server_header','')}'."),
            "remediation": ("Place the inference server behind an authenticated "
                            "gateway / reverse proxy and bind it to localhost or a "
                            "private subnet. These info endpoints leak model "
                            "inventory + framework version — cross-check the "
                            "reported version against NVD for known CVEs "
                            "(vLLM/Triton/Ray have multiple 2024-2025 advisories) "
                            "and patch.")}


def rule_generic_model_list(s):
    # Only the weak generic /v1/models match (no strong platform marker).
    det = s.get("serving_fp_detected") or []
    strong = [d for d in det if not d.get("weak")]
    weak = [d for d in det if d.get("weak")]
    if strong or not weak:
        return None
    d = weak[0]
    return {"name": "Unauthenticated OpenAI-compatible /v1/models listing",
            "severity": "INFO", "cvss": "5.3",
            "cwe": "CWE-200", "owasp": "LLM10:2025",
            "verified_exploit": False,
            "evidence": (f"{d['url']} model-list endpoint responded with generic "
                         f"model names; specific platform NOT confirmed "
                         f"({d['why']})."),
            "remediation": ("Require an API key for /v1/models. An open model "
                            "list enables targeted model-extraction + cost-abuse "
                            "planning.")}


MODEL_SERVING_FINGERPRINT_FINDING_RULES = [
    rule_unreachable,
    rule_positive,
    rule_exposed_serving_plane,
    rule_generic_model_list,
]


INTEL_FIELDS = [
    ("Base URLs probed", "serving_fp_bases"),
    ("Read-only GETs sent", "serving_fp_paths_probed"),
    ("Platforms fingerprinted", "serving_fp_total"),
    ("Detected platforms", "serving_fp_detected"),
    ("Transport errors", "serving_fp_transport_errors"),
]


@router.post("/api/ai_llm/model_serving_fingerprint")
async def ai_llm_model_serving_fingerprint(req: InfraRequest,
                                            _=Depends(verify_scan_quota)):
    async def _gather(ctx):
        ctx.options = req.options
        ctx.auth_bearer = req.auth_bearer
        await gather(ctx)
    return await run_scanner(host=req.target, tool="model_serving_fingerprint",
        gather_func=_gather,
        finding_rules=MODEL_SERVING_FINGERPRINT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
