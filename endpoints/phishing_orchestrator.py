"""phishing module orchestrator - email-security posture + impersonation
exposure + landing-page surface audit, plus honest advisory-by-design INFO
for the attacker-tradecraft techniques a SaaS scanner cannot probe.

Per module_playbooks/26_phishing.md - 7 sections / 70 techniques. The module
implements every technique that is externally OBSERVABLE as a real, safe
detection probe (VA, not PT) and emits the rest as honest INFO.

  - tier1_posture (email-security + impersonation exposure for the domain):
        spf_dkim_dmarc_audit   (SPF/DKIM/DMARC DNS TXT — §1 #5/#6) [REAL]
        lookalike_domain_scan  (typosquat / homoglyph / TLD-swap A — §2
                                #19/#20) [REAL]
        mailbox_security_audit (STARTTLS + cipher + cert on MX — §1 #4 +
                                §2) [REAL]
        mta_sts_tls_audit      (MTA-STS / TLS-RPT / DANE transport fence —
                                §1 cross-ref) [REAL]
        ct_log_lookalike_scan  (Certificate-Transparency lookalike-cert
                                detection — §2 #19/#20, §6) [REAL]
        oauth_tenant_exposure  (public M365/Entra OAuth + device-code
                                surface — §5 #43/#47) [REAL metadata]

  - tier2_simulation (login-page surface probes + inert artifacts):
        phishing_template_generate (inert HTML email template — §1 #7)
        landing_page_clone_test    (structural login-page clone — §2
                                    #15/#17/#18)
        bitb_frameability_check    (X-Frame-Options / CSP frame-ancestors —
                                    §3 #26 BitB) [REAL]
        open_redirect_probe        (off-site redirect capability via inert
                                    .invalid canary — §2 #21) [REAL]

  - tier3_advisory (honest [ADVISORY-BY-DESIGN] INFO, vulnerable:false):
        social_eng_advisory        (§1 send / §3 AiTM / §4 smish-vish-quish
                                    / §5 consent-lure delivery / §6 deepfake
                                    / §7 campaign console)

GoPhish / EvilGinx2 / SET / Modlishka wrappers are NOT shipped — they need
attacker infrastructure (sending IP, callback collector, spoof-domain TLS
cert) and a victim to act against. Those live as the tier3_advisory INFO
findings: the honest boundary of an external assessment, not a forge gap.

Concurrency hard-clamped to 4: the tier1 probes do DNS fan-out
(spf_dkim_dmarc_audit ~20 lookups, lookalike_domain_scan ~60) plus a few
HTTP GETs (MTA-STS well-known, crt.sh, OAuth metadata) and one blocking
STARTTLS handshake. Four concurrent scanners keeps wall-clock reasonable
without saturating a single DNS resolver; the open/HTTP probes are not
DNS-heavy so a small bump over the original 3 is safe.
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
        # Real external probes added in the deepening pass:
        ("mta_sts_tls_audit",          "/api/phishing/mta_sts_tls_audit"),
        ("ct_log_lookalike_scan",      "/api/phishing/ct_log_lookalike_scan"),
        ("oauth_tenant_exposure",      "/api/phishing/oauth_tenant_exposure"),
    ],
    "tier2_simulation": [
        ("phishing_template_generate", "/api/phishing/phishing_template_generate"),
        ("landing_page_clone_test",    "/api/phishing/landing_page_clone_test"),
        # Real external probes against a customer-supplied login/redirect URL:
        ("bitb_frameability_check",    "/api/phishing/bitb_frameability_check"),
        ("open_redirect_probe",        "/api/phishing/open_redirect_probe"),
    ],
    "tier3_advisory": [
        # Honest advisory-by-design INFO for techniques a SaaS scanner
        # cannot probe (attacker infra / outbound send / post-compromise /
        # deepfake media / campaign console). All findings are INFO.
        ("social_eng_advisory",        "/api/phishing/social_eng_advisory"),
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
    # Default fan-out concurrency = 4. The DNS-heavy tier1 probes
    # (spf_dkim_dmarc_audit, lookalike_domain_scan) can saturate a single
    # resolver if too many run at once; 4 keeps wall-clock reasonable for
    # the now-larger scanner set without overrunning the resolver.
    concurrency: Optional[int] = 4
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
    # Hard-clamp concurrency to 4 (Phishing module rule — DNS-resolver safe).
    concurrency = max(1, min(req.concurrency or 4, 4))
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
    concurrency = max(1, min(req.concurrency or 4, 4))
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
