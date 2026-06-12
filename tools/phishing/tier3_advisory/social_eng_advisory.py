"""social_eng_advisory - Honest advisory-by-design INFO coverage for the
phishing playbook techniques that cannot be probed from an external SaaS
scanner (module_playbooks/26_phishing.md §1-§7 tradecraft / delivery /
post-compromise / human-OPSEC items).

This scanner runs NO network I/O. It simply emits one INFO-only
[ADVISORY-BY-DESIGN] finding per playbook section whose techniques require
out-of-SaaS-scope execution (attacker infra, outbound send to a human,
post-compromise foothold, or creative/manual work). Every finding is
severity INFO with vulnerable:false - it is the honest boundary of VA, not
a forge gap or a scaffold, and it NEVER passes a playbook's planned attack
severity through as a finding severity.

It complements the module's live external probes:
  - spf_dkim_dmarc_audit / mta_sts_tls_audit  (email-auth + transport fence)
  - lookalike_domain_scan / ct_log_lookalike_scan (impersonation infra)
  - mailbox_security_audit                    (inbound TLS posture)
  - bitb_frameability_check / open_redirect_probe (landing-page surface)
  - oauth_tenant_exposure                     (M365 OAuth surface)

Customer input via ScanRequest.target = email domain (only echoed back).
"""
from __future__ import annotations
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.social_eng_advisory_findings import (
    SOCIAL_ENG_ADVISORY_FINDING_RULES,
)

router = APIRouter()


class SocialEngAdvisoryRequest(ScanRequest):
    options: Optional[dict] = None


async def gather(ctx: ScanContext):
    domain = (ctx.host or "").strip()
    # No probing — just mark which advisory sections to emit. The rules
    # read this flag and produce the INFO findings. We always emit so the
    # report has explicit, honest coverage of the out-of-scope surface.
    ctx.state["advisory_target"] = domain or "(target)"
    ctx.state["advisory_emit"] = True
    ctx.source("advisory-by-design enumeration (no network I/O)")


INTEL_FIELDS = [
    ("Target",                "advisory_target"),
]


@router.post("/api/phishing/social_eng_advisory")
async def phishing_social_eng_advisory(req: SocialEngAdvisoryRequest,
                                       _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="social_eng_advisory",
        gather_func=_gather_with_options,
        finding_rules=SOCIAL_ENG_ADVISORY_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
