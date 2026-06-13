"""hash_identification_advisory - §4 Hash Identification (advisory-by-design).

module_playbooks/08_password.md §4 lists 8 hash-identification techniques
(hashid, name-that-hash, hash-identifier, magic-byte detection, WPA mode
22000, Crackstation / hashes.com lookups).

Hash identification operates on a hash the customer ALREADY HAS - it is a
local/input-driven analysis step, not something an external scanner can run
against a remote target. There is no remote surface to probe. This endpoint
returns an honest INFO advisory via the canonical run_scanner + FINDING_RULES
pattern (advisory-by-design, never graded above INFO).
"""
from __future__ import annotations
from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools.password.tier6_advisory.hash_identification_advisory_findings import (
    HASH_IDENTIFICATION_ADVISORY_FINDING_RULES,
)

router = APIRouter()

TITLE = "Hash identification (hashid / name-that-hash) - §4"
REASON = (
    "Identifying a hash format (NTLM vs bcrypt vs Argon2 vs WPA 22000, "
    "etc.) is performed on a hash the customer already possesses, using "
    "hashid / name-that-hash / hash-identifier locally. It is an "
    "input-driven analysis step with no remote attack surface to scan."
)


async def gather(ctx: ScanContext):
    ctx.state["advisory"] = True
    ctx.state["advisory_title"] = TITLE
    ctx.state["advisory_reason"] = REASON
    ctx.state["advisory_cwe"] = "CWE-327"
    # Real source attribution: advisory-by-design, derived from the
    # playbook §4 catalogue, NOT from a live scan of the target.
    ctx.source("advisory-by-design (local hash analysis on customer-held input, no remote surface)")


INTEL_FIELDS = [("§4 Hash identification", "advisory_title")]


@router.post("/api/password/hash_identification_advisory")
async def hash_identification_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target,
        tool="hash_identification_advisory",
        gather_func=gather,
        finding_rules=HASH_IDENTIFICATION_ADVISORY_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
