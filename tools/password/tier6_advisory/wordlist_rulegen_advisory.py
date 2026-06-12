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
This endpoint returns an honest INFO advisory for the generation techniques.
"""
from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._pack_common import _advisory_by_design_response

router = APIRouter()


@router.post("/api/password/wordlist_rulegen_advisory")
def wordlist_rulegen_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _advisory_by_design_response(
        tool="wordlist_rulegen_advisory",
        target=req.target,
        title="Wordlist & rule generation (SecLists / crunch / cewl / hashcat rules) - §5",
        reason=(
            "Generating candidate wordlists and mutation rules (crunch, cewl, "
            "best64/OneRuleToRuleThemAll, Markov, PRINCE, mask, combinator, "
            "AI-curated lists) produces input for offline/online cracking - it is "
            "a local generation step, not a remote scan. The breach-exposure side "
            "(HIBP Pwned Passwords) IS probed live by breach_exposure_audit."
        ),
        cwe="CWE-521",
    )


def register(app):
    app.include_router(router)
