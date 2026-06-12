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
returns an honest INFO advisory - it is advisory-by-design, NOT a forge gap.
"""
from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._pack_common import _advisory_by_design_response

router = APIRouter()


@router.post("/api/password/os_credential_extraction_advisory")
def os_credential_extraction_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _advisory_by_design_response(
        tool="os_credential_extraction_advisory",
        target=req.target,
        title="OS-specific credential extraction (SAM / LSASS / NTDS.dit / Keychain) - §7",
        reason=(
            "Dumping SAM/SYSTEM hives, LSASS memory (Mimikatz/NanoDump), NTDS.dit, "
            "DPAPI master keys, /etc/shadow, the macOS Keychain, or browser-saved "
            "passwords all require an existing administrative/root foothold ON the "
            "host (post-compromise, MITRE ATT&CK Credential Access TA0006). An "
            "external scanner has no such foothold - these are advisory-by-design "
            "and belong to a manual / red-team / post-exploitation engagement."
        ),
        cwe="CWE-522",
    )


def register(app):
    app.include_router(router)
