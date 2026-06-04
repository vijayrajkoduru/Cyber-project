"""client_side module orchestrator - modern frontend security probes.

Per module_playbooks/09_client_side.md - 7 sections / 72 techniques.
This starter set (5 scanners) covers the highest-impact DOM + JS
attack surface that the basic Webapp module does NOT exercise:

  - tier1_dom (Document Object Model surface):
        csp_bypass_audit       (CSP weakness classes — playbook §5/§7)
        xss_dom_sinks_audit    (source→sink dataflow — playbook §1/§5)
        postmessage_audit      (window.message origin checks — §5/§7)

  - tier2_js (JS-runtime + cross-origin surface):
        prototype_pollution_test  (Object.prototype contamination — §5)
        cors_preflight_audit      (Access-Control-Allow-* misconfig — §5)

Concurrency is held at 3 because two of the probes (xss_dom_sinks_audit
and prototype_pollution_test) crawl + fetch many sub-assets — running
all five in parallel can hammer the customer's CDN.

More scanners will be added per playbook section in subsequent commits
(Phase C-2 = §1 BeEF hook hosting, §3 HTA gen; Phase C-3 = §4 LNK +
§6 social-eng delivery probes; etc.).
"""
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_parallel, run_module_streaming

router = APIRouter()


CLIENT_SIDE_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_dom": [
        ("csp_bypass_audit",          "/api/client_side/csp_bypass_audit"),
        ("xss_dom_sinks_audit",       "/api/client_side/xss_dom_sinks_audit"),
        ("postmessage_audit",         "/api/client_side/postmessage_audit"),
    ],
    "tier2_js": [
        ("prototype_pollution_test",  "/api/client_side/prototype_pollution_test"),
        ("cors_preflight_audit",      "/api/client_side/cors_preflight_audit"),
    ],
}


def _all_tools():
    out = []
    for tier in CLIENT_SIDE_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class ClientSideRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    # Default fan-out concurrency = 3 (per playbook rule — crawling probes
    # can saturate the customer's CDN if all 5 run in parallel).
    concurrency: Optional[int] = 3
    # Per-tool body extras (forwarded into req.options of each scanner)
    options: Optional[dict] = None


def _resolve(req: ClientSideRunAllRequest, request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in CLIENT_SIDE_TOOLS_BY_TIER:
                tools.extend(CLIENT_SIDE_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    extra: dict = {}
    if req.options:
        # Nest under "options" so each scanner can read it via
        # req.options (every Client-Side ScanRequest subclass carries .options).
        extra["options"] = req.options
    return tools, extra or None, jwt


@router.post("/api/client_side/run_all")
async def client_side_run_all(req: ClientSideRunAllRequest, request: Request,
                                _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    # Hard-clamp concurrency to 3 (Client-Side module rule).
    concurrency = max(1, min(req.concurrency or 3, 3))
    gen = run_module_streaming(
        target=req.target, tools=tools, module_name="client_side",
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


@router.post("/api/client_side/run_all_buffered")
async def client_side_run_all_buffered(req: ClientSideRunAllRequest, request: Request,
                                          _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 3, 3))
    return await run_module_parallel(
        target=req.target, tools=tools, module_name="client_side",
        concurrency=concurrency, extra_body=extra, jwt_token=jwt,
    )


@router.get("/api/client_side/run_all/tiers")
async def client_side_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in CLIENT_SIDE_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in CLIENT_SIDE_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
