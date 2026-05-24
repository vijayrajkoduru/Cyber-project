"""Webapp module orchestrator endpoint — VL-FORGE v2 streaming.

Same pattern as endpoints/recon_orchestrator.py but for the 34 web-application
pentest scanners. Single POST /api/scan/run_all replaces 34 sequential frontend
calls. Backend fans out to every /api/scan/<tool> endpoint in parallel via the
shared orchestrator engine in tools/_framework/orchestrator.py.

Expected speedup on a real target: ~10 min sequential -> ~60-90 sec parallel.

Tier organization mirrors the existing PHASES list in App.js so the frontend
can render tier-filter checkboxes ("Quick scan: Recon + Injection only").
"""
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from tools._shared import verify_scan_quota
from tools._framework.orchestrator import (
    run_module_parallel, run_module_streaming,
)

router = APIRouter()


WEBAPP_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    # Discovery — runs FIRST so other scanners can use scan_state.json
    "tier1_discovery": [
        ("spa_crawler", "/api/webapp/scan/spa_crawler"),
    ],
    # Recon & Fingerprinting
    # (dns / techstack / ssl_cert removed — they live in tools/recon/, not
    #  tools/webapp/ — the Recon module already handles them. Keeping the
    #  webapp module focused on app-layer tests only.)
    "tier2_recon": [
        ("cms",      "/api/webapp/scan/cms"),
        ("ssl",      "/api/webapp/scan/ssl"),
        ("portscan", "/api/webapp/scan/portscan"),
    ],
    # Injection Attacks (highest customer impact)
    "tier3_injection": [
        ("xss",            "/api/webapp/scan/xss"),
        ("sqli",           "/api/webapp/scan/sqli"),
        ("cmd_injection",  "/api/webapp/scan/cmd_injection"),
        ("xxe",            "/api/webapp/scan/xxe"),
    ],
    # Authentication & Session
    "tier4_auth": [
        ("headers", "/api/webapp/scan/headers"),     # security_headers route alias
        ("cookies", "/api/webapp/scan/cookies"),
        ("csrf",    "/api/webapp/scan/csrf"),
        ("jwt",     "/api/webapp/scan/jwt"),
    ],
    # File & Path
    "tier5_file_path": [
        ("lfi",           "/api/webapp/scan/lfi"),
        ("exposed_files", "/api/webapp/scan/exposed_files"),
    ],
    # Network & Protocol
    "tier6_network": [
        ("cors",          "/api/webapp/scan/cors"),
        ("ssrf",          "/api/webapp/scan/ssrf"),
        ("http_methods",  "/api/webapp/scan/http_methods"),
        ("open_redirect", "/api/webapp/scan/open_redirect"),
        ("clickjacking",  "/api/webapp/scan/clickjacking"),
    ],
    # Access Control & Modern API
    "tier7_access": [
        ("idor",            "/api/webapp/scan/idor"),
        ("mass_assignment", "/api/webapp/scan/mass_assignment"),
        ("nosql",           "/api/webapp/scan/nosql"),
        ("access_control",  "/api/webapp/scan/access_control"),
    ],
    # Framework-specific + Heavy
    "tier8_framework": [
        ("nikto",          "/api/webapp/scan/nikto"),
        ("nuclei",         "/api/webapp/scan/nuclei"),
        ("force_browse",   "/api/webapp/scan/force_browse"),
        ("file_upload",    "/api/webapp/scan/file_upload"),
        ("ssti",           "/api/webapp/scan/ssti"),
        ("graphql",        "/api/webapp/scan/graphql"),
        ("sensitive_data", "/api/webapp/scan/sensitive_data"),
        ("stored_xss",     "/api/webapp/scan/stored_xss"),
        ("wpscan",         "/api/webapp/scan/wpscan"),
    ],
    # Tier 9 — AI-curated discovery (newly forged, big wordlists, async-parallel)
    "tier9_ai_curated_discovery": [
        ("directory_brute",  "/api/webapp/directory_brute"),    # 940 paths
        ("param_discovery",  "/api/webapp/param_discovery"),    # 577 names
        ("crawler",          "/api/webapp/crawler"),            # 203 seeds
        ("secrets",          "/api/webapp/secrets"),            # 97 regex patterns
    ],
    # Tier 10 — Modern attack-surface coverage (AI-curated payload lists)
    "tier10_modern_attacks": [
        ("nosqli",                "/api/webapp/nosqli"),                # 20 MongoDB operators
        ("ldap_injection",        "/api/webapp/ldap_injection"),        # 20 LDAP filter probes
        ("crlf_injection",        "/api/webapp/crlf_injection"),        # 18 CRLF variants
        ("prototype_pollution",   "/api/webapp/prototype_pollution"),   # 19 gadgets
        ("host_header_injection", "/api/webapp/host_header_injection"), # 25 header variants
        ("cache_poisoning",       "/api/webapp/cache_poisoning"),       # 25 unkeyed headers
        ("deserialization_probe", "/api/webapp/deserialization_probe"), # 53 markers
        ("http_smuggling",        "/api/webapp/http_smuggling"),        # CL.TE timing probe
    ],
}


def _all_tools() -> list[tuple[str, str]]:
    out = []
    for tier in WEBAPP_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class WebAppRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None       # subset, e.g. ["tier3_injection"]
    concurrency: Optional[int] = 8          # max in-flight tool calls
    auth_cookie: Optional[str] = None       # SPA session cookie (forwarded)
    auth_bearer: Optional[str] = None       # JWT bearer (forwarded)
    options: Optional[dict] = None          # per-scanner options (rare)


def _resolve_tools_and_jwt(req: "WebAppRunAllRequest", request: Request):
    """Common request unpacking."""
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in WEBAPP_TOOLS_BY_TIER:
                tools.extend(WEBAPP_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()

    extra = {}
    if req.options:
        extra.update(req.options)

    auth_header = request.headers.get("authorization") or ""
    jwt_token = None
    if auth_header.lower().startswith("bearer "):
        jwt_token = auth_header.split(" ", 1)[1].strip()

    return tools, extra, jwt_token


@router.post("/api/webapp/scan/run_all")
async def webapp_run_all(req: "WebAppRunAllRequest",
                          request: Request,
                          _=Depends(verify_scan_quota)):
    """Stream per-scanner results as NDJSON. See run_module_streaming for shape.

    Each event line:
      {"event":"scan_started", "module":"webapp", "target":"...", "total_tools":...}
      {"event":"tool_complete", "tool":..., "duration_sec":..., "result":{...}}
      ... N tool_complete events ...
      {"event":"heartbeat", "elapsed_sec":..., "completed":N, "total":M, "in_flight":...}
      {"event":"scan_complete", "duration_sec":..., "summary":{...}, "timing":{...}}
    """
    tools, extra, jwt_token = _resolve_tools_and_jwt(req, request)
    # VL-TURBO — default concurrency 8→12. 34 webapp tools / 12 ≈ 3 waves
    # instead of 5; httpx connection pool already allows up to 36 keepalives.
    concurrency = max(1, min(req.concurrency or 12, 16))

    generator = run_module_streaming(
        target=req.target,
        tools=tools,
        module_name="webapp",
        concurrency=concurrency,
        auth_cookie=req.auth_cookie,
        auth_bearer=req.auth_bearer,
        extra_body=extra or None,
        jwt_token=jwt_token,
    )
    return StreamingResponse(
        generator,
        media_type="application/x-ndjson",
        headers={
            "X-Accel-Buffering": "no",
            "Cache-Control":     "no-store, no-transform",
            "Connection":        "keep-alive",
        },
    )


@router.post("/api/webapp/scan/run_all_buffered")
async def webapp_run_all_buffered(req: "WebAppRunAllRequest",
                                    request: Request,
                                    _=Depends(verify_scan_quota)):
    """Non-streaming version — buffers all 34 results then returns one big JSON.
    Use only when streaming isn't suitable (CLI tools, server-to-server)."""
    tools, extra, jwt_token = _resolve_tools_and_jwt(req, request)
    # VL-TURBO — default concurrency 8→12. 34 webapp tools / 12 ≈ 3 waves
    # instead of 5; httpx connection pool already allows up to 36 keepalives.
    concurrency = max(1, min(req.concurrency or 12, 16))
    return await run_module_parallel(
        target=req.target,
        tools=tools,
        module_name="webapp",
        concurrency=concurrency,
        auth_cookie=req.auth_cookie,
        auth_bearer=req.auth_bearer,
        extra_body=extra or None,
        jwt_token=jwt_token,
    )


@router.get("/api/webapp/scan/run_all/tiers")
async def webapp_run_all_tiers():
    """Discovery endpoint — list tier IDs the frontend can filter by."""
    return {
        "tiers": [
            {"id": tier_id, "tools": [name for name, _ in tools],
              "count": len(tools)}
            for tier_id, tools in WEBAPP_TOOLS_BY_TIER.items()
        ],
        "total_tools": sum(len(t) for t in WEBAPP_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
