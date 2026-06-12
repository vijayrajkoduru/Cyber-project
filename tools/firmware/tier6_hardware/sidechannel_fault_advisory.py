"""sidechannel_fault_advisory - side-channel & fault injection (playbook §7 #59-#66).

ADVISORY-BY-DESIGN. The §7 techniques — ChipWhisperer power analysis, voltage
glitching, clock glitch injection, EM injection, laser fault injection, power-
analysis key recovery — are LABORATORY hardware attacks requiring physical
possession of the target, a glitch/capture rig (ChipWhisperer, oscilloscope,
EM probe, laser station), and often device decapping. They are categorically
impossible to perform from an external SaaS against an uploaded firmware blob,
and several are inherently DESTRUCTIVE / DoS-adjacent — out of scope for a VA
(detection-only) product.

This scanner emits a single honest [ADVISORY-BY-DESIGN] INFO describing the
manual procedure + defensive guidance. It never fabricates a graded finding.

Customer input: ScanRequest.target = optional path to firmware blob (unused
for detection — these attacks target silicon, not the image).
"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.sidechannel_fault_advisory_findings import SIDECHANNEL_FAULT_ADVISORY_FINDING_RULES

router = APIRouter()

TECHNIQUES = [
    "ChipWhisperer power (DPA/CPA) analysis",
    "ChipWhisperer voltage glitching",
    "Clock glitch injection",
    "EM (electromagnetic) fault injection",
    "Laser fault injection (decap required)",
    "Power-analysis AES/RSA key recovery",
]


async def gather(ctx: ScanContext):
    ctx.state["sca_techniques"] = TECHNIQUES
    ctx.state["sca_advisory"] = True
    ctx.state["sidechannel_fault_advisory_total"] = 0
    ctx.source("advisory-by-design (lab hardware + physical silicon access required)")


INTEL_FIELDS = [("Side-channel / fault techniques (lab)", "sca_techniques")]


@router.post("/api/firmware/sidechannel_fault_advisory")
async def firmware_sidechannel_fault_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="sidechannel_fault_advisory",
        gather_func=gather, finding_rules=SIDECHANNEL_FAULT_ADVISORY_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
