"""nfc_rfid_advisory - NFC / RFID attack-family advisory (playbook §7 #67-74).

ADVISORY-BY-DESIGN. NFC/RFID techniques (tag read/clone, MIFARE Classic key
crack, HID Prox / iCLASS / DESFire attacks, relay attacks) require physical
proximity (centimeters) AND specialized hardware (Proxmark3, Flipper Zero, NFC
reader). They are entirely physical-layer and cannot be probed from any network
SaaS scanner.

Emits INFO-only [ADVISORY-BY-DESIGN] findings. Planned severities are in
remediation text only; never the finding severity.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.nfc_rfid_advisory_findings import NFC_RFID_ADVISORY_FINDING_RULES

router = APIRouter()


async def gather(ctx: ScanContext):
    ctx.state["nfc_rfid_advisory"] = True
    ctx.state["nfc_rfid_advisory_total"] = 0
    ctx.source("advisory-by-design (NFC/RFID is physical-layer; needs Proxmark/Flipper HW)")


INTEL_FIELDS = [("Coverage", "nfc_rfid_advisory")]


@router.post("/api/wireless/nfc_rfid_advisory")
async def wireless_nfc_rfid_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="nfc_rfid_advisory",
        gather_func=gather, finding_rules=NFC_RFID_ADVISORY_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
