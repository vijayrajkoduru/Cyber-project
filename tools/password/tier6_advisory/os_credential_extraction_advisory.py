"""os_credential_extraction_advisory - §7 OS-specific Password Extraction
(advisory-by-design).

module_playbooks/08_password.md §7 lists 12 OS-credential-extraction
techniques (SAM/SYSTEM hive dump, LSASS/Mimikatz, NTDS.dit, DPAPI, Windows
Credential Manager, /etc/shadow, macOS Keychain, browser saved passwords,
password-vault extraction, browser session-token theft, NanoDump).

EVERY technique in this section is POST-COMPROMISE: it requires an existing
administrative/root foothold ON the host (local code execution, SYSTEM/root
privileges, physical or RDP/SSH session). An external SaaS vulnerability
scanner has no such foothold and cannot perform any of them. This endpoint
returns an honest INFO advisory via the canonical run_scanner + FINDING_RULES
pattern - it is advisory-by-design, NOT a forge gap, and never graded above
INFO.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools.password.tier6_advisory.os_credential_extraction_advisory_findings import (
    OS_CREDENTIAL_EXTRACTION_ADVISORY_FINDING_RULES,
)

router = APIRouter()

TITLE = "OS-specific credential extraction (SAM / LSASS / NTDS.dit / Keychain) - §7"
REASON = (
    "Dumping SAM/SYSTEM hives, LSASS memory (Mimikatz/NanoDump), NTDS.dit, "
    "DPAPI master keys, /etc/shadow, the macOS Keychain, or browser-saved "
    "passwords all require an existing administrative/root foothold ON the "
    "host (post-compromise, MITRE ATT&CK Credential Access TA0006). An "
    "external scanner has no such foothold - these are advisory-by-design "
    "and belong to a manual / red-team / post-exploitation engagement."
)


async def gather(ctx: ScanContext):
    ctx.state["advisory"] = True
    ctx.state["advisory_title"] = TITLE
    ctx.state["advisory_reason"] = REASON
    ctx.state["advisory_cwe"] = "CWE-522"
    # Real source attribution: advisory-by-design, derived from the
    # playbook §7 catalogue, NOT from a live scan of the target.
    ctx.source("advisory-by-design (post-compromise credential access, no external foothold)")


INTEL_FIELDS = [("§7 OS credential extraction", "advisory_title")]


@router.post("/api/password/os_credential_extraction_advisory")
async def os_credential_extraction_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target,
        tool="os_credential_extraction_advisory",
        gather_func=gather,
        finding_rules=OS_CREDENTIAL_EXTRACTION_ADVISORY_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
