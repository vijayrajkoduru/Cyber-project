"""Vulnerability Scanning module orchestrator — VL-FORGE v2 streaming.

Same engine as endpoints/recon_orchestrator.py and webapp_orchestrator.py.
Registers the 19 scanners that VulnModule exposes — a focused subset of
the WebApp toolset (no Discovery/Modern-API tests, but adds Nikto on top).

The shared engine in tools/_framework/orchestrator.py handles the parallel
dispatch, NDJSON event streaming, heartbeats, and per-tool error isolation.

POST /api/vuln/run_all          — NDJSON stream (default for dashboard)
POST /api/vuln/run_all_buffered — single big JSON (CLI / scripts)
GET  /api/vuln/run_all/tiers    — discovery for tier-filter UI
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


VULN_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    # Generic vuln scanners (heavy, take longest)
    "tier1_heavy": [
        ("nikto",  "/api/scan/nikto"),
        ("nuclei", "/api/scan/nuclei"),
        ("wpscan", "/api/scan/wpscan"),
    ],
    # TLS + headers + cookies (fast, almost always run)
    "tier2_transport": [
        ("ssl",      "/api/scan/ssl"),
        ("headers",  "/api/scan/headers"),
        ("cors",     "/api/scan/cors"),
        ("cookies",  "/api/scan/cookies"),
    ],
    # Fingerprinting
    "tier3_fingerprint": [
        ("cms", "/api/scan/cms"),
    ],
    # Injection attacks (highest customer impact)
    "tier4_injection": [
        ("xss",           "/api/scan/xss"),
        ("sqli",          "/api/scan/sqli"),
        ("cmd_injection", "/api/scan/cmd_injection"),
        ("xxe",           "/api/scan/xxe"),
    ],
    # File / path
    "tier5_file_path": [
        ("lfi",           "/api/scan/lfi"),
        ("exposed_files", "/api/scan/exposed_files"),
    ],
    # Network / protocol
    "tier6_network": [
        ("open_redirect", "/api/scan/open_redirect"),
        ("ssrf",          "/api/scan/ssrf"),
        ("http_methods",  "/api/scan/http_methods"),
    ],
    # Auth / session
    "tier7_auth": [
        ("csrf", "/api/scan/csrf"),
        ("jwt",  "/api/scan/jwt"),
    ],
}


def _all_tools() -> list[tuple[str, str]]:
    out = []
    for tier in VULN_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class VulnRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    # Bumped 8 -> 12 after the 2026-05-23 stall on vulnuslab.com (Cloudflare-fronted).
    # With 19 scanners and concurrency=8, 11 sit idle while nikto/wpscan/ssl/nuclei
    # block 4 of the 8 slots for 60-120s. 12 lets cors/cookies/cms/etc fly through
    # while the heavies run. Still safe for target WAF — most tools are read-only.
    concurrency: Optional[int] = 12
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None
    options: Optional[dict] = None


def _resolve_tools_and_jwt(req: "VulnRunAllRequest", request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in VULN_TOOLS_BY_TIER:
                tools.extend(VULN_TOOLS_BY_TIER[tier])
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


@router.post("/api/vuln/run_all")
async def vuln_run_all(req: "VulnRunAllRequest",
                        request: Request,
                        _=Depends(verify_scan_quota)):
    """Stream per-scanner results as NDJSON. See run_module_streaming for shape."""
    tools, extra, jwt_token = _resolve_tools_and_jwt(req, request)
    concurrency = max(1, min(req.concurrency or 12, 16))

    generator = run_module_streaming(
        target=req.target,
        tools=tools,
        module_name="vuln",
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


@router.post("/api/vuln/run_all_buffered")
async def vuln_run_all_buffered(req: "VulnRunAllRequest",
                                  request: Request,
                                  _=Depends(verify_scan_quota)):
    """Non-streaming version — buffers all 19 results then returns one big JSON."""
    tools, extra, jwt_token = _resolve_tools_and_jwt(req, request)
    concurrency = max(1, min(req.concurrency or 12, 16))
    return await run_module_parallel(
        target=req.target,
        tools=tools,
        module_name="vuln",
        concurrency=concurrency,
        auth_cookie=req.auth_cookie,
        auth_bearer=req.auth_bearer,
        extra_body=extra or None,
        jwt_token=jwt_token,
    )


@router.get("/api/vuln/run_all/tiers")
async def vuln_run_all_tiers():
    """Discovery endpoint — list tier IDs."""
    return {
        "tiers": [
            {"id": tier_id, "tools": [name for name, _ in tools],
              "count": len(tools)}
            for tier_id, tools in VULN_TOOLS_BY_TIER.items()
        ],
        "total_tools": sum(len(t) for t in VULN_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
