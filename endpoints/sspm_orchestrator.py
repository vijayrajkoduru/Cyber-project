"""sspm module orchestrator - SaaS Security Posture Management.

Per module_playbooks/29_sspm.md - 8 sections, 88 techniques.
Starter set (5 scanners) covers the highest-impact SaaS providers:

  - tier1_microsoft   (§1 Microsoft 365 Posture):
        m365_security_score
  - tier2_google      (§2 Google Workspace Posture):
        gworkspace_admin_audit
  - tier3_other_saas  (§3 Salesforce, §4 Slack, §6 GitHub Org):
        salesforce_org_audit, slack_workspace_audit, github_org_audit

Concurrency defaults to 3. SaaS admin APIs throttle aggressively per-tenant:
  - Microsoft Graph: ~10k req / 10 min per app
  - Google Admin SDK: 2400 req / minute project-wide
  - Slack Web API: tier-2/3 methods 20 req / minute
  - GitHub REST: 5000 req / hour per PAT
Three concurrent probes keep us well inside every envelope while letting
the slowest single-probe wall-clock define the run time.

All probes are READ-ONLY. Customer-supplied tokens/secrets flow through
options and are NEVER persisted server-side.

ScanRequest.target = label for the SaaS tenant (e.g. "acme.com" or
"vulnuslab GitHub org"). Per-probe credentials live under options:
  options.tenant_id / .client_id / .client_secret      (M365)
  options.gcp_service_account_json / .delegated_admin  (Google Workspace)
  options.sf_domain / .sf_access_token                  (Salesforce)
  options.slack_bot_token                                (Slack)
  options.github_token / .github_org                     (GitHub Org)
"""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_parallel, run_module_streaming

router = APIRouter()


SSPM_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_microsoft": [
        ("m365_security_score",      "/api/sspm/m365_security_score"),
    ],
    "tier2_google": [
        ("gworkspace_admin_audit",   "/api/sspm/gworkspace_admin_audit"),
    ],
    "tier3_other_saas": [
        ("salesforce_org_audit",     "/api/sspm/salesforce_org_audit"),
        ("slack_workspace_audit",    "/api/sspm/slack_workspace_audit"),
        ("github_org_audit",         "/api/sspm/github_org_audit"),
    ],
}


def _all_tools():
    out = []
    for tier in SSPM_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class SspmRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    # SaaS admin APIs rate-limit aggressively — default fan-out concurrency 3.
    concurrency: Optional[int] = 3
    # Per-probe credentials packed under options.{tenant_id, client_id, ...}.
    # See the module docstring for the full key map.
    options: Optional[dict] = None


def _resolve(req: SspmRunAllRequest, request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in SSPM_TOOLS_BY_TIER:
                tools.extend(SSPM_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    # Nest customer options so each scanner reads it via req.options
    # (every SSPM probe subclasses ScanRequest with options: dict).
    extra: dict = {}
    if req.options:
        extra["options"] = req.options
    return tools, extra or None, jwt


@router.post("/api/sspm/run_all")
async def sspm_run_all(req: SspmRunAllRequest, request: Request,
                       _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    # Hard-clamp concurrency to 5 (SaaS admin APIs throttle per-tenant).
    concurrency = max(1, min(req.concurrency or 3, 5))
    gen = run_module_streaming(
        target=req.target, tools=tools, module_name="sspm",
        concurrency=concurrency, extra_body=extra, jwt_token=jwt,
    )
    return StreamingResponse(
        gen,
        media_type="application/x-ndjson",
        headers={
            "X-Accel-Buffering": "no",
            "Cache-Control":     "no-store, no-transform",
            "Connection":        "keep-alive",
        },
    )


@router.post("/api/sspm/run_all_buffered")
async def sspm_run_all_buffered(req: SspmRunAllRequest, request: Request,
                                 _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 3, 5))
    return await run_module_parallel(
        target=req.target, tools=tools, module_name="sspm",
        concurrency=concurrency, extra_body=extra, jwt_token=jwt,
    )


@router.get("/api/sspm/run_all/tiers")
async def sspm_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in SSPM_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in SSPM_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
