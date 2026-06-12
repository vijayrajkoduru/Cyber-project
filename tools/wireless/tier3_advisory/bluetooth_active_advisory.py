"""bluetooth_active_advisory - Bluetooth/BLE ACTIVE attack-family advisory
(playbook §6 #57-66; the active attacks beyond passive enumeration).

ADVISORY-BY-DESIGN. BLE pairing weak-key attacks, replay, sniffing (Ubertooth/
nRF), Classic PIN brute (redfang), BlueBorne (CVE-2017-0781), BIAS, KNOB-style
forward-secrecy attacks, BlueJacking/BlueSnarfing all require physical RF
proximity (often specialized sniffer hardware) and active interaction with the
target device. The tier2_bluetooth scanners already do the SAFE passive
enumeration; this scanner documents the ACTIVE attacks that VulnusLab does not
perform from SaaS.

Emits INFO-only [ADVISORY-BY-DESIGN] findings. Planned severities are in
remediation text only; never the finding severity.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.bluetooth_active_advisory_findings import (
    BLUETOOTH_ACTIVE_ADVISORY_FINDING_RULES,
)

router = APIRouter()


async def gather(ctx: ScanContext):
    ctx.state["bluetooth_active_advisory"] = True
    ctx.state["bluetooth_active_advisory_total"] = 0
    ctx.source("advisory-by-design (active BT/BLE attacks require RF proximity + sniffer HW)")


INTEL_FIELDS = [("Coverage", "bluetooth_active_advisory")]


@router.post("/api/wireless/bluetooth_active_advisory")
async def wireless_bluetooth_active_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="bluetooth_active_advisory",
        gather_func=gather, finding_rules=BLUETOOTH_ACTIVE_ADVISORY_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
