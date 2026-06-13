"""offline_crack_advisory - §2 Offline Hash Cracking (advisory-by-design).

module_playbooks/08_password.md §2 lists 16 offline hash-cracking
techniques (hashcat/john across NTLM, NetNTLMv2, Kerberos TGS/AS-REP,
bcrypt, scrypt, Argon2, PBKDF2, JWT HS256, archive/vault formats, etc.).

NONE of these can be performed by an external SaaS vulnerability scanner:
offline cracking requires the customer to PROVIDE the captured hash(es) and
runs on dedicated GPU hardware. There is nothing to "scan" on a remote
target. This endpoint returns an honest INFO advisory via the canonical
run_scanner + FINDING_RULES pattern (advisory-by-design, never graded).

The LIVE password-attack surface that CAN be detected remotely is covered
by tier1_spray/auth_surface_audit, tier4_discovery/breach_exposure_audit,
and the AD roasting scanners in tier3_ad.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools.password.tier6_advisory.offline_crack_advisory_findings import (
    OFFLINE_CRACK_ADVISORY_FINDING_RULES,
)

router = APIRouter()

TITLE = "Offline hash cracking (hashcat / john) - §2"
REASON = (
    "Offline cracking of NTLM, NetNTLMv2, Kerberos (Kerberoast/AS-REP), "
    "bcrypt, scrypt, Argon2, PBKDF2, JWT HS256, and archive/vault hashes "
    "requires the customer to supply the captured hash material and runs "
    "on dedicated GPU hardware - there is no remote surface to scan. Use "
    "hashcat/john with SecLists + best64/OneRule rules on an isolated rig. "
    "Detection of the live spray/brute surface those hashes come from is "
    "covered by auth_surface_audit and the tier3_ad roasting scanners."
)


async def gather(ctx: ScanContext):
    ctx.state["advisory"] = True
    ctx.state["advisory_title"] = TITLE
    ctx.state["advisory_reason"] = REASON
    ctx.state["advisory_cwe"] = "CWE-916"
    # Real source attribution: advisory-by-design, derived from the
    # playbook §2 catalogue, NOT from a live scan of the target.
    ctx.source("advisory-by-design (offline cracking on customer-supplied hashes, no remote surface)")


INTEL_FIELDS = [("§2 Offline hash cracking", "advisory_title")]


@router.post("/api/password/offline_crack_advisory")
async def offline_crack_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target,
        tool="offline_crack_advisory",
        gather_func=gather,
        finding_rules=OFFLINE_CRACK_ADVISORY_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
