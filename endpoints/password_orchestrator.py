"""password module orchestrator - online + offline password attacks.

Per module_playbooks/08_password.md - 8 sections, 90 techniques.
Starter set (5 scanners) covers the highest-impact playbook items:
  - tier1_spray (§1 Online Password Attacks):
        hydra_ssh_spray, ncrack_rdp_spray, medusa_smb_spray,
        patator_http_form_brute
  - tier2_crack (§2 Offline Hash Cracking):
        john_hash_audit
More scanners will be added per playbook section in subsequent commits.

Concurrency is intentionally LOW (2) because password modules hammer a
single target with N x M attempts each - running more than two against
the same host simultaneously trips account-lockout policies and WAF
rate-limiters, polluting the result set.
"""
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_parallel, run_module_streaming

router = APIRouter()


PASSWORD_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_spray": [
        ("hydra_ssh_spray",          "/api/password/hydra_ssh_spray"),
        ("ncrack_rdp_spray",         "/api/password/ncrack_rdp_spray"),
        ("medusa_smb_spray",         "/api/password/medusa_smb_spray"),
        ("patator_http_form_brute",  "/api/password/patator_http_form_brute"),
    ],
    "tier2_crack": [
        ("john_hash_audit",          "/api/password/john_hash_audit"),
    ],
}


def _all_tools():
    out = []
    for tier in PASSWORD_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class PasswordRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 2
    options: Optional[dict] = None


def _resolve(req: PasswordRunAllRequest, request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in PASSWORD_TOOLS_BY_TIER:
                tools.extend(PASSWORD_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    # Nest the customer options dict so each scanner can read it via
    # req.options (the orchestrator flattens extra_body into the per-tool body).
    extra: dict = {}
    if req.options:
        extra["options"] = req.options
    return tools, extra or None, jwt


@router.post("/api/password/run_all")
async def password_run_all(req: PasswordRunAllRequest, request: Request,
                            _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    # Hard-clamp concurrency to 2 (password module rule per memory).
    concurrency = max(1, min(req.concurrency or 2, 2))
    gen = run_module_streaming(
        target=req.target, tools=tools, module_name="password",
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


@router.post("/api/password/run_all_buffered")
async def password_run_all_buffered(req: PasswordRunAllRequest, request: Request,
                                     _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 2, 2))
    return await run_module_parallel(
        target=req.target, tools=tools, module_name="password",
        concurrency=concurrency, extra_body=extra, jwt_token=jwt,
    )


@router.get("/api/password/run_all/tiers")
async def password_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in PASSWORD_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in PASSWORD_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
