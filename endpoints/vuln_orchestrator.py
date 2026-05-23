"""Vulnerability Scanning module orchestrator — VL-FORGE v2 streaming.

INDUSTRY-ALIGNED REBUILD (2026-05-24): the Vuln module is now a TRUE
infrastructure/host vulnerability scanner — matches what Nessus / OpenVAS /
Qualys VMDR / Rapid7 InsightVM do. The webapp-style scanners (xss, sqli,
csrf, jwt, etc.) live in the isolated Webapp module at /api/webapp/scan/*.

16 tools across 5 tiers:

  Tier 1 — CVE & Template Scanners (3 tools)
    nuclei, wpscan, nikto

  Tier 2 — Discovery & Service Detection (4 tools)
    portscan, service_detect, os_fingerprint, internetdb

  Tier 3 — Crypto & TLS (1 tool)
    ssl_deep

  Tier 4 — Credentials (1 tool)
    default_creds

  Tier 5 — Service Enumeration (7 tools)
    snmp_enum, smb_enum, ftp_enum, smtp_enum, nfs_check, db_exposure_check, cve_match

Routes: every scanner answers at /api/vuln/<tool>. The orchestrator
streams NDJSON from /api/vuln/run_all. Cloudflare-safe (heartbeats every
15s). Same V2 framework as Recon and Webapp.
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
    # Tier 1 — Heavy CVE / template scanners (slowest, run first so others
    # have time to complete in parallel)
    "tier1_heavy": [
        ("nuclei",          "/api/vuln/nuclei"),
        ("wpscan",          "/api/vuln/wpscan"),
        ("nikto",           "/api/vuln/nikto"),
    ],
    # Tier 2 — Discovery & service detection (port scan informs the
    # enumeration scanners — but we run parallel via async, not strict-serial)
    "tier2_discovery": [
        ("portscan",        "/api/vuln/portscan"),
        ("service_detect",  "/api/vuln/service_detect"),
        ("os_fingerprint",  "/api/vuln/os_fingerprint"),
        ("internetdb",      "/api/vuln/internetdb"),
    ],
    # Tier 3 — Crypto / TLS deep audit
    "tier3_crypto": [
        ("ssl_deep",        "/api/vuln/ssl_deep"),
    ],
    # Tier 4 — Credential & auth surface
    "tier4_credentials": [
        ("default_creds",   "/api/vuln/default_creds"),
    ],
    # Tier 5 — Service enumeration (SNMP/SMB/FTP/SMTP/NFS/DB) + CVE lookup
    "tier5_enumeration": [
        ("snmp_enum",            "/api/vuln/snmp_enum"),
        ("smb_enum",             "/api/vuln/smb_enum"),
        ("ftp_enum",             "/api/vuln/ftp_enum"),
        ("smtp_enum",            "/api/vuln/smtp_enum"),
        ("nfs_check",            "/api/vuln/nfs_check"),
        ("db_exposure_check",    "/api/vuln/db_exposure_check"),
        ("cve_match",            "/api/vuln/cve_match"),
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
    # VL-TURBO — default concurrency 8→12. 16 vuln tools / 12 ≈ 2 waves.
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
    """Non-streaming version — buffers all 16 results then returns one big JSON."""
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
