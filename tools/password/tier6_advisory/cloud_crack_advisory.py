"""cloud_crack_advisory - §6 Cloud Distributed Cracking (advisory-by-design).

module_playbooks/08_password.md §6 lists 8 cloud/distributed cracking
techniques (Hashtopolis, vast.ai/RunPod GPU rental, AWS EC2 spot, NPK,
single-GPU benchmark, cross-cloud crack-as-a-service, hashcat in K8s GPU
pods, cost-vs-time optimization).

These are operator-side INFRASTRUCTURE techniques for accelerating offline
cracking on rented/owned GPUs. They have no relationship to a remote target
and cannot be scanned for. This endpoint returns an honest INFO advisory.
"""
from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._pack_common import _advisory_by_design_response

router = APIRouter()


@router.post("/api/password/cloud_crack_advisory")
def cloud_crack_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _advisory_by_design_response(
        tool="cloud_crack_advisory",
        target=req.target,
        title="Cloud distributed cracking (Hashtopolis / NPK / GPU rental) - §6",
        reason=(
            "Distributing hashcat across rented or owned GPU fleets (Hashtopolis, "
            "vast.ai/RunPod, AWS EC2 spot, NPK, K8s GPU pods) is operator-side "
            "infrastructure for accelerating offline cracking. It targets the "
            "operator's own compute, not the customer's environment - there is no "
            "remote surface to scan."
        ),
        cwe="CWE-916",
    )


def register(app):
    app.include_router(router)
