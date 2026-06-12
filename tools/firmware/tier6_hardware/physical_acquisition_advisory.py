"""physical_acquisition_advisory - physical firmware acquisition (playbook §1 #3-#7, #10).

ADVISORY-BY-DESIGN. The §1 acquisition techniques that need PHYSICAL hardware
access — firmware blob extraction via UART, SPI flash chip dump (BusPirate /
CH341A), eMMC / NAND chip-off, in-circuit JTAG/SWD dump, bootloader recovery-
mode dump, and SDR-based OTA capture — cannot be performed by an external SaaS.
They require possession of the device, rework/soldering or clip adapters, and
bench tooling.

(The SaaS-reachable §1 techniques — vendor download over HTTPS/FTP and cloud
firmware-mirror S3-bucket enumeration — belong to the Recon / Cloud modules and
are intentionally NOT duplicated here.)

This scanner emits a single honest [ADVISORY-BY-DESIGN] INFO with the manual
procedure. It never fabricates a graded finding.

Customer input: ScanRequest.target = optional path (unused — acquisition
produces the blob; it cannot be inferred from one).
"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.physical_acquisition_advisory_findings import PHYSICAL_ACQUISITION_ADVISORY_FINDING_RULES

router = APIRouter()

TECHNIQUES = [
    "Firmware blob extraction via UART boot console",
    "SPI flash chip dump (BusPirate / CH341A clip)",
    "eMMC / NAND chip-off + reader",
    "In-circuit JTAG / SWD flash dump",
    "Bootloader recovery-mode dump",
    "SDR-based OTA update capture",
]


async def gather(ctx: ScanContext):
    ctx.state["acq_techniques"] = TECHNIQUES
    ctx.state["acq_advisory"] = True
    ctx.state["physical_acquisition_advisory_total"] = 0
    ctx.source("advisory-by-design (physical device + bench tooling required)")


INTEL_FIELDS = [("Physical acquisition techniques (manual)", "acq_techniques")]


@router.post("/api/firmware/physical_acquisition_advisory")
async def firmware_physical_acquisition_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="physical_acquisition_advisory",
        gather_func=gather, finding_rules=PHYSICAL_ACQUISITION_ADVISORY_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
