"""Recon module orchestrator endpoint — VL-FORGE v2.

Single POST /api/recon/run_all replaces 41 sequential frontend calls.
Backend fans out to every /api/recon/<tool> endpoint in parallel via
the shared orchestrator engine in tools/_framework/orchestrator.py.

Expected speedup: ~5 min (sequential) → ~30-60 sec (parallel) for a
fresh scan of a Cloudflare-fronted target.

Tier filtering: optional `tiers` field in the request body lets the
frontend run only a subset — e.g. tiers=["tier1_dns", "tier2_subdomain"]
for a 30-second smoke check before the full scan.
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


# Registry of every recon tool and its endpoint path. Tier-tagged so the
# frontend can run subsets. ORDER MATTERS for display but not execution
# (orchestrator runs in parallel regardless of list order).
RECON_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_dns": [
        ("whois",         "/api/recon/whois"),
        ("dns",           "/api/recon/dns"),
        ("dnsrecon",      "/api/recon/dnsrecon"),
        ("zone_transfer", "/api/recon/zone_transfer"),
    ],
    "tier2_subdomain": [
        ("subdomains", "/api/recon/subdomains"),
        ("crtsh",      "/api/recon/crtsh"),
        ("amass",      "/api/recon/amass"),
        ("cdn_origin", "/api/recon/cdn_origin"),
    ],
    "tier3_network": [
        ("masscan",  "/api/recon/masscan"),   # portscan.py registers this route
        ("nmap",     "/api/recon/nmap"),
        ("services", "/api/recon/services"),
        ("os",       "/api/recon/os"),
        ("banner",   "/api/recon/banner"),
    ],
    "tier4_web": [
        ("gobuster",    "/api/recon/gobuster"),
        ("jsendpoints", "/api/recon/jsendpoints"),
        ("wayback",     "/api/recon/wayback"),
        ("robotsmap",   "/api/recon/robotsmap"),
        ("crawl",       "/api/recon/crawl"),
        ("params",      "/api/recon/params"),
        ("favicon",     "/api/recon/favicon"),
    ],
    "tier5_cloud": [
        ("cloudbuckets", "/api/recon/cloudbuckets"),
        ("bucket_perms", "/api/recon/bucket_perms"),
        ("asn",          "/api/recon/asn"),
    ],
    "tier6_threat": [
        ("shodan",     "/api/recon/shodan"),
        ("internetdb", "/api/recon/internetdb"),
        ("cve_match",  "/api/recon/cve_match"),
        ("waf_cdn",    "/api/recon/waf_cdn"),
        ("harvester",  "/api/recon/harvester"),
    ],
    "tier7_app": [
        ("sourcemap",     "/api/recon/sourcemap"),
        ("api_docs",      "/api/recon/api_docs"),
        ("tls_deep",      "/api/recon/tls_deep"),
        ("wpjson_enum",   "/api/recon/wpjson_enum"),
        ("default_creds", "/api/recon/default_creds"),
        ("jslib_cve",     "/api/recon/jslib_cve"),
        ("git_recon",     "/api/recon/git_recon"),
    ],
    "tier8_osint": [
        ("breach_search",      "/api/recon/breach_search"),
        ("github_leaks",       "/api/recon/github_leaks"),
        ("graphql_introspect", "/api/recon/graphql_introspect"),
        ("email_security",     "/api/recon/email_security"),
        ("dork_harvest",       "/api/recon/dork_harvest"),
        ("dnssec_validate",    "/api/recon/dnssec_validate"),
    ],
}


def _all_tools() -> list[tuple[str, str]]:
    out = []
    for tier in RECON_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class RunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None       # subset, e.g. ["tier1_dns","tier2_subdomain"]
    concurrency: Optional[int] = 8          # max in-flight tool calls
    auth_cookie: Optional[str] = None       # SPA session cookie (forwarded to each tool)
    auth_bearer: Optional[str] = None       # JWT bearer (forwarded to each tool)
    shodan_api_key: Optional[str] = None    # tier6 shodan needs this


def _resolve_tools_and_jwt(req: "RunAllRequest", request: Request):
    """Common request unpacking — used by both the streaming + buffered routes."""
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in RECON_TOOLS_BY_TIER:
                tools.extend(RECON_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()

    extra = {}
    if req.shodan_api_key:
        extra["api_key"] = req.shodan_api_key

    auth_header = request.headers.get("authorization") or ""
    jwt_token = None
    if auth_header.lower().startswith("bearer "):
        jwt_token = auth_header.split(" ", 1)[1].strip()

    return tools, extra, jwt_token


# ─────────────────────────────────────────────────────────────────
# /api/recon/run_all — NDJSON STREAMING (default since 2026-05-23)
# ─────────────────────────────────────────────────────────────────
# Streams one JSON line per tool completion + opening + closing events.
# First byte goes out within ~1-3s, beating Cloudflare's 100s TTFB ceiling.
# Frontend reads ReadableStream line-by-line and updates tiles as each
# tool finishes — replaces the all-tiles-update-at-once UX of buffered v2.
#
# Header hints to bypass intermediary buffering:
#   X-Accel-Buffering: no   — nginx (your frontend container's nginx)
#   Cache-Control:    no-store, no-transform
#   Content-Type:     application/x-ndjson
@router.post("/api/recon/run_all")
async def recon_run_all(req: "RunAllRequest",
                          request: Request,
                          _=Depends(verify_scan_quota)):
    """Stream per-tool results as NDJSON. See run_module_streaming for shape."""
    tools, extra, jwt_token = _resolve_tools_and_jwt(req, request)
    concurrency = max(1, min(req.concurrency or 8, 16))

    generator = run_module_streaming(
        target=req.target,
        tools=tools,
        module_name="recon",
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
            "X-Accel-Buffering": "no",          # nginx must NOT buffer
            "Cache-Control":     "no-store, no-transform",
            "Connection":        "keep-alive",
        },
    )


# Legacy buffered endpoint preserved for callers that don't want to deal with
# streaming (CLI scripts, tests, internal automation). Same shape as the
# original v2 response (single JSON object with tools{} + summary{}).
@router.post("/api/recon/run_all_buffered")
async def recon_run_all_buffered(req: "RunAllRequest",
                                    request: Request,
                                    _=Depends(verify_scan_quota)):
    """Non-streaming v2 — buffers all results then returns one big JSON.
    Use only when streaming isn't suitable (CLI tools, server-to-server)."""
    tools, extra, jwt_token = _resolve_tools_and_jwt(req, request)
    concurrency = max(1, min(req.concurrency or 8, 16))
    return await run_module_parallel(
        target=req.target,
        tools=tools,
        module_name="recon",
        concurrency=concurrency,
        auth_cookie=req.auth_cookie,
        auth_bearer=req.auth_bearer,
        extra_body=extra or None,
        jwt_token=jwt_token,
    )


@router.get("/api/recon/run_all/tiers")
async def recon_run_all_tiers():
    """Discovery endpoint: list the tier IDs the frontend can select.

    Used by the UI to render tier-filter checkboxes ("Quick scan: Tier 1-2 only").
    """
    return {
        "tiers": [
            {"id": tier_id, "tools": [name for name, _ in tools],
              "count": len(tools)}
            for tier_id, tools in RECON_TOOLS_BY_TIER.items()
        ],
        "total_tools": sum(len(t) for t in RECON_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
