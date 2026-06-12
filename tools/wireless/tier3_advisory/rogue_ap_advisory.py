"""rogue_ap_advisory - Rogue AP / Evil Twin attack-family advisory
(playbook §5 #45-54).

ADVISORY-BY-DESIGN. Rogue AP / Evil Twin techniques (hostapd-wpe rogue AP,
airbase-ng evil twin, wifiphisher, Karma + captive-portal injection, DHCP/DNS
spoofing on a rogue AP, forced-association deauth, Wi-Fi Pineapple workflow,
EAP-Pickle) are ACTIVE attacks that broadcast a malicious access point on the
target RF. They are inherently PT (not VA), require RF hardware + physical
proximity, and would be disruptive. VulnusLab is detection-only and never runs
these.

Emits INFO-only [ADVISORY-BY-DESIGN] findings. Planned severities are in
remediation text only; never the finding severity.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.rogue_ap_advisory_findings import ROGUE_AP_ADVISORY_FINDING_RULES

router = APIRouter()


async def gather(ctx: ScanContext):
    ctx.state["rogue_ap_advisory"] = True
    ctx.state["rogue_ap_advisory_total"] = 0
    ctx.source("advisory-by-design (rogue AP / evil twin are active PT, not VA)")


INTEL_FIELDS = [("Coverage", "rogue_ap_advisory")]


@router.post("/api/wireless/rogue_ap_advisory")
async def wireless_rogue_ap_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="rogue_ap_advisory",
        gather_func=gather, finding_rules=ROGUE_AP_ADVISORY_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
