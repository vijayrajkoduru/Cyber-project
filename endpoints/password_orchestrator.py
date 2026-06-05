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
from tools._methodology import ChainExecutor, chain_registry

router = APIRouter()


PASSWORD_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_spray": [
        ("hydra_ssh_spray",          "/api/password/hydra_ssh_spray"),
        ("ncrack_rdp_spray",         "/api/password/ncrack_rdp_spray"),
        ("medusa_smb_spray",         "/api/password/medusa_smb_spray"),
        ("patator_http_form_brute",  "/api/password/patator_http_form_brute"),
        ("ftp_brute",                "/api/password/ftp_brute"),
        ("mysql_brute",              "/api/password/mysql_brute"),
        ("postgres_brute",           "/api/password/postgres_brute"),
        ("ldap_brute",               "/api/password/ldap_brute"),
    ],
    "tier2_crack": [
        ("john_hash_audit",          "/api/password/john_hash_audit"),
    ],
    "tier3_ad": [
        ("kerberoast_audit",         "/api/password/kerberoast_audit"),
        ("asreproast_audit",         "/api/password/asreproast_audit"),
        ("dcsync_audit",             "/api/password/dcsync_audit"),
        ("bloodhound_audit",         "/api/password/bloodhound_audit"),
    ],
    "tier4_discovery": [
        ("git_secrets_scan",         "/api/password/git_secrets_scan"),
        ("exposed_env_scan",         "/api/password/exposed_env_scan"),
    ],
    "tier5_web": [
        ("jwt_forge_audit",          "/api/password/jwt_forge_audit"),
        ("session_predict_audit",    "/api/password/session_predict_audit"),
        ("oauth_token_audit",        "/api/password/oauth_token_audit"),
        ("saml_signature_audit",     "/api/password/saml_signature_audit"),
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
    response = await run_module_parallel(
        target=req.target, tools=tools, module_name="password",
        concurrency=concurrency, extra_body=extra, jwt_token=jwt,
    )

    # ── Chain expansion ───────────────────────────────────────────
    # For each primary result that emitted chain_next via VL-METHOD
    # Stage 7, spawn the suggested downstream scanners with inherited
    # credentials. ALWAYS attach chain_summary so callers can introspect
    # the registry even when no chains executed (Test 5 health check).
    if (req.options or {}).get("enable_chaining", True):
        if isinstance(response, dict):
            response.setdefault("chain_summary", {
                "chained_scans": 0,
                "chained_scanners": [],
                "registered_chain_scanners": chain_registry.known(),
            })
        try:
            results_list = []
            if isinstance(response, dict):
                results_list = list(response.get("results") or [])
            if results_list:
                executor = ChainExecutor(chain_registry)
                chained = await executor.expand_all(
                    primary_results=results_list,
                    target=req.target,
                    jwt=jwt,
                )
                if chained:
                    response["results"] = results_list + chained
                    response["chain_summary"] = {
                        "chained_scans": len(chained),
                        "chained_scanners": sorted({
                            r.get("tool") for r in chained if r.get("tool")
                        }),
                        "registered_chain_scanners": chain_registry.known(),
                    }
        except Exception as e:
            # Don't fail the whole response if chaining errors
            response.setdefault("chain_summary", {})["error"] = (
                f"{type(e).__name__}: {str(e)[:200]}"
            )

    return response


@router.get("/api/password/run_all/tiers")
async def password_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in PASSWORD_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in PASSWORD_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
