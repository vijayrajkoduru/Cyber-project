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
        ("spa_crawler", "/api/scan/spa_crawler"),
    ],
    # Recon & Fingerprinting
    # (dns / techstack / ssl_cert removed — they live in tools/recon/, not
    #  tools/webapp/ — the Recon module already handles them. Keeping the
    #  webapp module focused on app-layer tests only.)
    "tier2_recon": [
        ("cms",      "/api/scan/cms"),
        ("ssl",      "/api/scan/ssl"),
        ("portscan", "/api/scan/portscan"),
    ],
    # Injection Attacks (highest customer impact)
    "tier3_injection": [
        ("xss",            "/api/scan/xss"),
        ("sqli",           "/api/scan/sqli"),
        ("cmd_injection",  "/api/scan/cmd_injection"),
        ("xxe",            "/api/scan/xxe"),
    ],
    # Authentication & Session
    "tier4_auth": [
        ("headers", "/api/scan/headers"),     # security_headers route alias
        ("cookies", "/api/scan/cookies"),
        ("csrf",    "/api/scan/csrf"),
        ("jwt",     "/api/scan/jwt"),
    ],
    # File & Path
    "tier5_file_path": [
        ("lfi",           "/api/scan/lfi"),
        ("exposed_files", "/api/scan/exposed_files"),
    ],
    # Network & Protocol
    "tier6_network": [
        ("cors",          "/api/scan/cors"),
        ("ssrf",          "/api/scan/ssrf"),
        ("http_methods",  "/api/scan/http_methods"),
        ("open_redirect", "/api/scan/open_redirect"),
        ("clickjacking",  "/api/scan/clickjacking"),
    ],
    # Access Control & Modern API
    "tier7_access": [
        ("idor",            "/api/scan/idor"),
        ("mass_assignment", "/api/scan/mass_assignment"),
        ("nosql",           "/api/scan/nosql"),
        ("access_control",  "/api/scan/access_control"),
    ],
    # Framework-specific + Heavy
    "tier8_framework": [
        ("nikto",          "/api/scan/nikto"),
        ("nuclei",         "/api/scan/nuclei"),
        ("force_browse",   "/api/scan/force_browse"),
        ("file_upload",    "/api/scan/file_upload"),
        ("ssti",           "/api/scan/ssti"),
        ("graphql",        "/api/scan/graphql"),
        ("sensitive_data", "/api/scan/sensitive_data"),
        ("stored_xss",     "/api/scan/stored_xss"),
        ("wpscan",         "/api/scan/wpscan"),
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


@router.post("/api/scan/run_all")
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
    concurrency = max(1, min(req.concurrency or 8, 16))

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


@router.post("/api/scan/run_all_buffered")
async def webapp_run_all_buffered(req: "WebAppRunAllRequest",
                                    request: Request,
                                    _=Depends(verify_scan_quota)):
    """Non-streaming version — buffers all 34 results then returns one big JSON.
    Use only when streaming isn't suitable (CLI tools, server-to-server)."""
    tools, extra, jwt_token = _resolve_tools_and_jwt(req, request)
    concurrency = max(1, min(req.concurrency or 8, 16))
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


@router.get("/api/scan/run_all/tiers")
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
