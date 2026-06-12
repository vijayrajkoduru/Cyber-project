"""client_side module orchestrator - modern frontend security probes.

Per module_playbooks/09_client_side.md - 7 sections / 72 techniques.
This set covers the live-probeable DOM + JS + browser-hardening attack
surface (real graded detection against a remote target) plus an honest
advisory-by-design tier for the payload-craft / red-team-infrastructure
techniques that CANNOT be detected from an external SaaS VA scan.

  - tier1_dom (Document Object Model + browser-hardening surface):
        csp_bypass_audit              (CSP weakness classes — §5/§7)
        xss_dom_sinks_audit           (source->sink dataflow — §1/§5)
        postmessage_audit             (window.message origin checks — §5/§7)
        clickjacking_audit            (XFO + frame-ancestors — §5 #40)
        cross_origin_isolation_audit  (COOP/COEP/CORP — §5 #41/#42, §7 #69)
        permissions_policy_audit      (camera/usb/serial/hid — §1/§7 #66/#67)

  - tier2_js (JS-runtime + cross-origin + supply-chain surface):
        prototype_pollution_test      (Object.prototype contamination — §5)
        cors_preflight_audit          (Access-Control-Allow-* misconfig — §5)
        subresource_integrity_audit   (third-party SRI / supply-chain — §5 #43)
        service_worker_audit          (SW persistence / scope — §7 #65)
        open_redirect_param_audit     (reflected open redirect — §6 #54)

  - tier3_advisory (honest advisory-by-design, INFO-only):
        clientside_advisory_surface   (BeEF/macro/HTA/LNK/browser-CVE/
                                       phishing-infra/AiTM — §1-§7 PT-only)

ZERO false positives: every graded (CRITICAL/HIGH/MEDIUM/LOW) finding is
emitted ONLY when the live probe actually observed the condition on the
target. Everything that needs operator-side payload delivery, victim
execution, or red-team infrastructure is INFO [ADVISORY-BY-DESIGN].

Concurrency is held at 3 because several probes (xss_dom_sinks_audit,
prototype_pollution_test, subresource_integrity_audit, service_worker_audit)
crawl + fetch many sub-assets — running them all in parallel can hammer
the customer's CDN.
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
        ("csp_bypass_audit",              "/api/client_side/csp_bypass_audit"),
        ("xss_dom_sinks_audit",           "/api/client_side/xss_dom_sinks_audit"),
        ("postmessage_audit",             "/api/client_side/postmessage_audit"),
        ("clickjacking_audit",            "/api/client_side/clickjacking_audit"),
        ("cross_origin_isolation_audit",  "/api/client_side/cross_origin_isolation_audit"),
        ("permissions_policy_audit",      "/api/client_side/permissions_policy_audit"),
    ],
    "tier2_js": [
        ("prototype_pollution_test",      "/api/client_side/prototype_pollution_test"),
        ("cors_preflight_audit",          "/api/client_side/cors_preflight_audit"),
        ("subresource_integrity_audit",   "/api/client_side/subresource_integrity_audit"),
        ("service_worker_audit",          "/api/client_side/service_worker_audit"),
        ("open_redirect_param_audit",     "/api/client_side/open_redirect_param_audit"),
    ],
    "tier3_advisory": [
        ("clientside_advisory_surface",   "/api/client_side/clientside_advisory_surface"),
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
