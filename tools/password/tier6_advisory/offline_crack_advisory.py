"""offline_crack_advisory - §2 Offline Hash Cracking (advisory-by-design).

module_playbooks/08_password.md §2 lists 16 offline hash-cracking
techniques (hashcat/john across NTLM, NetNTLMv2, Kerberos TGS/AS-REP,
bcrypt, scrypt, Argon2, PBKDF2, JWT HS256, archive/vault formats, etc.).

NONE of these can be performed by an external SaaS vulnerability scanner:
offline cracking requires the customer to PROVIDE the captured hash(es) and
runs on dedicated GPU hardware. There is nothing to "scan" on a remote
target. This endpoint therefore returns an honest INFO advisory describing
the technique catalogue and how to run it, rather than a fabricated finding.

The LIVE password-attack surface that CAN be detected remotely is covered
by tier1_spray/auth_surface_audit, tier4_discovery/breach_exposure_audit,
and the AD roasting scanners in tier3_ad.
"""
from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._pack_common import _advisory_by_design_response

router = APIRouter()


@router.post("/api/password/offline_crack_advisory")
def offline_crack_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _advisory_by_design_response(
        tool="offline_crack_advisory",
        target=req.target,
        title="Offline hash cracking (hashcat / john) - §2",
        reason=(
            "Offline cracking of NTLM, NetNTLMv2, Kerberos (Kerberoast/AS-REP), "
            "bcrypt, scrypt, Argon2, PBKDF2, JWT HS256, and archive/vault hashes "
            "requires the customer to supply the captured hash material and runs "
            "on dedicated GPU hardware - there is no remote surface to scan. Use "
            "hashcat/john with SecLists + best64/OneRule rules on an isolated rig. "
            "Detection of the live spray/brute surface those hashes come from is "
            "covered by auth_surface_audit and the tier3_ad roasting scanners."
        ),
        cwe="CWE-916",
    )


def register(app):
    app.include_router(router)
