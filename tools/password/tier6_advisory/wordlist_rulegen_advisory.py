"""wordlist_rulegen_advisory - §5 Password Wordlist & Rule Gen
(advisory-by-design).

module_playbooks/08_password.md §5 lists 12 wordlist / rule-generation
techniques (SecLists/rockyou, crunch, cewl, hashcat rule files, john
--rules, Markov/PRINCE/mask/combinator attacks, AI-curated wordlists, HIBP
Pwned Passwords k-anonymity).

Wordlist and rule generation produce ATTACK INPUT for offline cracking and
online spraying; they are local generation steps, not remote scans. The one
exception with a remote surface - HIBP Pwned Passwords / breach exposure -
is implemented as a live probe in tier4_discovery/breach_exposure_audit.
This endpoint returns an honest INFO advisory via the canonical run_scanner
+ FINDING_RULES pattern (advisory-by-design, never graded above INFO).
"""
from __future__ import annotations
from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools.password.tier6_advisory.wordlist_rulegen_advisory_findings import (
    WORDLIST_RULEGEN_ADVISORY_FINDING_RULES,
)

router = APIRouter()

TITLE = "Wordlist & rule generation (SecLists / crunch / cewl / hashcat rules) - §5"
REASON = (
    "Generating candidate wordlists and mutation rules (crunch, cewl, "
    "best64/OneRuleToRuleThemAll, Markov, PRINCE, mask, combinator, "
    "AI-curated lists) produces input for offline/online cracking - it is "
    "a local generation step, not a remote scan. The breach-exposure side "
    "(HIBP Pwned Passwords) IS probed live by breach_exposure_audit."
)


async def gather(ctx: ScanContext):
    ctx.state["advisory"] = True
    ctx.state["advisory_title"] = TITLE
    ctx.state["advisory_reason"] = REASON
    ctx.state["advisory_cwe"] = "CWE-521"
    # Real source attribution: advisory-by-design, derived from the
    # playbook §5 catalogue, NOT from a live scan of the target.
    ctx.source("advisory-by-design (local wordlist/rule generation, not a remote scan)")


INTEL_FIELDS = [("§5 Wordlist & rule generation", "advisory_title")]


@router.post("/api/password/wordlist_rulegen_advisory")
async def wordlist_rulegen_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target,
        tool="wordlist_rulegen_advisory",
        gather_func=gather,
        finding_rules=WORDLIST_RULEGEN_ADVISORY_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
