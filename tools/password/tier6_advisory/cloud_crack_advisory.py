"""cloud_crack_advisory - §6 Cloud Distributed Cracking (advisory-by-design).

module_playbooks/08_password.md §6 lists 8 cloud/distributed cracking
techniques (Hashtopolis, vast.ai/RunPod GPU rental, AWS EC2 spot, NPK,
single-GPU benchmark, cross-cloud crack-as-a-service, hashcat in K8s GPU
pods, cost-vs-time optimization).

These are operator-side INFRASTRUCTURE techniques for accelerating offline
cracking on rented/owned GPUs. They have no relationship to a remote target
and cannot be scanned for. This endpoint returns an honest INFO advisory
via the canonical run_scanner + FINDING_RULES pattern (advisory-by-design,
never graded above INFO).
"""
from __future__ import annotations
from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools.password.tier6_advisory.cloud_crack_advisory_findings import (
    CLOUD_CRACK_ADVISORY_FINDING_RULES,
)

router = APIRouter()

TITLE = "Cloud distributed cracking (Hashtopolis / NPK / GPU rental) - §6"
REASON = (
    "Distributing hashcat across rented or owned GPU fleets (Hashtopolis, "
    "vast.ai/RunPod, AWS EC2 spot, NPK, K8s GPU pods) is operator-side "
    "infrastructure for accelerating offline cracking. It targets the "
    "operator's own compute, not the customer's environment - there is no "
    "remote surface to scan."
)


async def gather(ctx: ScanContext):
    ctx.state["advisory"] = True
    ctx.state["advisory_title"] = TITLE
    ctx.state["advisory_reason"] = REASON
    ctx.state["advisory_cwe"] = "CWE-916"
    # Real source attribution: this finding is advisory-by-design, derived
    # from the playbook §6 catalogue, NOT from a live scan of the target.
    ctx.source("advisory-by-design (operator-side GPU infrastructure, no remote surface)")


INTEL_FIELDS = [("§6 Cloud / distributed cracking", "advisory_title")]


@router.post("/api/password/cloud_crack_advisory")
async def cloud_crack_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target,
        tool="cloud_crack_advisory",
        gather_func=gather,
        finding_rules=CLOUD_CRACK_ADVISORY_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
