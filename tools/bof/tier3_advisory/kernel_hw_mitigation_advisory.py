"""kernel_hw_mitigation_advisory - §6 #60 KASLR + §8 #75-#80 (advisory).

ADVISORY-BY-DESIGN. This tier covers the kernel-level and post-mitigation
bypass research techniques that a SaaS scanner of an uploaded userland binary
categorically cannot perform:

  §6 #60  KASLR bypass (kernel)          - needs a kernel info-leak primitive +
                                           on-host execution; not a userland file.
  §8 #75  Shadow-Stack (CET-SS) bypass   - requires a working exploit on CET HW.
  §8 #76  Win 11 ARM64EC mitigation bypass - research, on-device.
  §8 #77  macOS pointer-auth bypass      - research, on Apple-silicon device.
  §8 #78  iOS PAC bypass (CryptoLib)     - research, on-device + jailbreak chain.
  §8 #79  Hypervisor escape (KVM/Hyper-V CVE) - needs a guest VM foothold (post-
                                           compromise) + a specific CVE.
  §8 #80  TEE / SGX / TrustZone enclave bypass - needs the secure-world / enclave
                                           runtime + often physical/side-channel.

Every one of these needs a running kernel / hypervisor / secure-world, a
post-compromise foothold, specific silicon, or active research-grade
exploitation - never available to a detection-only SaaS over an uploaded file.
NOTE: the STATIC userland CFI opt-in markers (Intel CET IBT/SHSTK, ARM PAC/BTI)
ARE checked - by the real cfi_modern_mitigation_audit scanner. This advisory
covers only the bypass / kernel / cross-privilege research layer.

Customer input: ScanRequest.target = path to a binary (label only; nothing is
executed).
"""
from __future__ import annotations
from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools.bof.tier3_advisory.kernel_hw_mitigation_advisory_findings import (
    KERNEL_HW_MITIGATION_ADVISORY_FINDING_RULES,
)

router = APIRouter()

TECHNIQUES = [
    "KASLR bypass (kernel info-leak)",
    "Shadow-Stack (CET-SS) bypass",
    "Win 11 ARM64EC mitigation bypass",
    "macOS pointer-auth (PAC) bypass",
    "iOS PAC bypass (CryptoLib)",
    "Hypervisor escape (KVM / Hyper-V CVE)",
    "TEE / SGX / TrustZone enclave bypass",
]


async def gather(ctx: ScanContext):
    ctx.state["kern_techniques"] = TECHNIQUES
    ctx.state["kern_advisory"] = True
    ctx.source("advisory-by-design (kernel / hypervisor / secure-world + post-compromise required)")


INTEL_FIELDS = [("§6/§8 Kernel & HW-mitigation bypass research", "kern_techniques")]


@router.post("/api/bof/kernel_hw_mitigation_advisory")
async def bof_kernel_hw_mitigation_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target,
        tool="kernel_hw_mitigation_advisory",
        gather_func=gather,
        finding_rules=KERNEL_HW_MITIGATION_ADVISORY_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
