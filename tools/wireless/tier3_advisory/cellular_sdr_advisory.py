"""cellular_sdr_advisory - Cellular / 5G / SDR attack-family advisory
(playbook §8 #75-84).

ADVISORY-BY-DESIGN. Cellular and SDR techniques (IMSI catching, 5G NSA->SA
downgrade, SUPI/SUCI privacy attacks, SS7/Diameter abuse, OAI 5G testbed audit,
ADS-B/AIS/LoRa/POCSAG intercept) require RF hardware (RTL-SDR, HackRF, BladeRF),
physical RF proximity, and in many cases a licensed/legal testbed. Several are
legally restricted (transmitting on cellular bands). None is reachable from an
external SaaS scanner.

Emits INFO-only [ADVISORY-BY-DESIGN] findings. Planned severities are in
remediation text only; never the finding severity.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.cellular_sdr_advisory_findings import (
    CELLULAR_SDR_ADVISORY_FINDING_RULES,
)

router = APIRouter()


async def gather(ctx: ScanContext):
    ctx.state["cellular_sdr_advisory"] = True
    ctx.state["cellular_sdr_advisory_total"] = 0
    ctx.source("advisory-by-design (cellular/SDR needs RF hardware + licensed testbed)")


INTEL_FIELDS = [("Coverage", "cellular_sdr_advisory")]


@router.post("/api/wireless/cellular_sdr_advisory")
async def wireless_cellular_sdr_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="cellular_sdr_advisory",
        gather_func=gather, finding_rules=CELLULAR_SDR_ADVISORY_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
