"""hash_identification_advisory - §4 Hash Identification (advisory-by-design).

module_playbooks/08_password.md §4 lists 8 hash-identification techniques
(hashid, name-that-hash, hash-identifier, magic-byte detection, WPA mode
22000, Crackstation / hashes.com lookups).

Hash identification operates on a hash the customer ALREADY HAS - it is a
local/input-driven analysis step, not something an external scanner can run
against a remote target. There is no remote surface to probe. This endpoint
returns an honest INFO advisory rather than a fabricated finding.
"""
from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._pack_common import _advisory_by_design_response

router = APIRouter()


@router.post("/api/password/hash_identification_advisory")
def hash_identification_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _advisory_by_design_response(
        tool="hash_identification_advisory",
        target=req.target,
        title="Hash identification (hashid / name-that-hash) - §4",
        reason=(
            "Identifying a hash format (NTLM vs bcrypt vs Argon2 vs WPA 22000, "
            "etc.) is performed on a hash the customer already possesses, using "
            "hashid / name-that-hash / hash-identifier locally. It is an "
            "input-driven analysis step with no remote attack surface to scan."
        ),
        cwe="CWE-327",
    )


def register(app):
    app.include_router(router)
