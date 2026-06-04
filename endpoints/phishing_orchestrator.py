"""phishing module orchestrator - Phishing-LITE: email security posture
+ template + landing-page-clone audit.

Per module_playbooks/26_phishing.md - 7 sections / 70 techniques.
This LITE starter (5 scanners) covers the safe, customer-self-service
surface that requires NO outbound email and NO attacker infrastructure:

  - tier1_posture (email security posture for the target domain):
        spf_dkim_dmarc_audit   (DNS TXT records — playbook §1 #5/#6)
        lookalike_domain_scan  (typosquat / homoglyph / TLD-swap A —
                                playbook §2 #19/#20)
        mailbox_security_audit (STARTTLS + cipher + cert on MX —
                                playbook §1 #4 cross-ref + §2)

  - tier2_simulation (artifact generation — NO sending, NO deployment):
        phishing_template_generate (HTML email template — §1 #7)
        landing_page_clone_test    (HTML clone of login page — §2 #15/#17/#18)

GoPhish / EvilGinx2 / SET / Modlishka wrappers are NOT shipped here —
they require attacker infrastructure (sending IP, callback collector,
TLS cert for spoof domain) the customer must stand up themselves. The
LITE module ships the audit + the artifact; deployment is the
customer's call on their own controlled simulation infrastructure.

Concurrency held at 3 (per task brief): two probes do DNS fan-out
(spf_dkim_dmarc_audit ~20 lookups, lookalike_domain_scan ~60), one
runs a blocking STARTTLS handshake, and two produce in-process
artifacts only. Three concurrent scanners is the sweet spot — five
in parallel can saturate a single DNS resolver.

More scanners will be added per playbook section in subsequent commits
(Phase next: §3 AiTM EvilGinx wrapper, §5 OAuth consent phishing
detector, §4 SMS/voice probe via Twilio sandbox).
"""
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_parallel, run_module_streaming

router = APIRouter()


PHISHING_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_posture": [
        ("spf_dkim_dmarc_audit",       "/api/phishing/spf_dkim_dmarc_audit"),
        ("lookalike_domain_scan",      "/api/phishing/lookalike_domain_scan"),
        ("mailbox_security_audit",     "/api/phishing/mailbox_security_audit"),
    ],
    "tier2_simulation": [
        ("phishing_template_generate", "/api/phishing/phishing_template_generate"),
        ("landing_page_clone_test",    "/api/phishing/landing_page_clone_test"),
    ],
}


def _all_tools():
    out = []
    for tier in PHISHING_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class PhishingRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    # Default fan-out concurrency = 3 (per playbook rule — two probes
    # do DNS fan-out which can saturate a single resolver if all five
    # run in parallel).
    concurrency: Optional[int] = 3
    # Per-tool body extras (forwarded into req.options of each scanner)
    options: Optional[dict] = None


def _resolve(req: PhishingRunAllRequest, request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in PHISHING_TOOLS_BY_TIER:
                tools.extend(PHISHING_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    extra: dict = {}
    if req.options:
        # Nest under "options" so each scanner can read it via
        # req.options (every Phishing ScanRequest subclass carries .options).
        extra["options"] = req.options
    return tools, extra or None, jwt


@router.post("/api/phishing/run_all")
async def phishing_run_all(req: PhishingRunAllRequest, request: Request,
                            _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    # Hard-clamp concurrency to 3 (Phishing module rule).
    concurrency = max(1, min(req.concurrency or 3, 3))
    gen = run_module_streaming(
        target=req.target, tools=tools, module_name="phishing",
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


@router.post("/api/phishing/run_all_buffered")
async def phishing_run_all_buffered(req: PhishingRunAllRequest, request: Request,
                                      _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 3, 3))
    return await run_module_parallel(
        target=req.target, tools=tools, module_name="phishing",
        concurrency=concurrency, extra_body=extra, jwt_token=jwt,
    )


@router.get("/api/phishing/run_all/tiers")
async def phishing_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in PHISHING_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in PHISHING_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
