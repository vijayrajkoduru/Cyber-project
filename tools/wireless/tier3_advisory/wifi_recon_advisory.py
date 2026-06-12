"""wifi_recon_advisory - Wi-Fi recon/enumeration advisory for the techniques
that require monitor-mode RF (playbook §1, the parts not covered by
monitor_mode_capability_audit).

ADVISORY-BY-DESIGN. Hidden-SSID discovery, client probe-request enumeration,
channel-hopping scans, signal-strength mapping (kismet), Wigle GPS/war-driving,
and Wi-Fi 6/6E/7 + 6 GHz capability fingerprinting all require an on-air
monitor-mode capture adjacent to the target. The OUI vendor lookup (§1 #8) is
the only purely-offline item and is informational. None is reachable from an
external SaaS scanner.

Emits INFO-only [ADVISORY-BY-DESIGN] findings. Planned severities are in
remediation text only; never the finding severity.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.wifi_recon_advisory_findings import WIFI_RECON_ADVISORY_FINDING_RULES

router = APIRouter()


async def gather(ctx: ScanContext):
    ctx.state["wifi_recon_advisory"] = True
    ctx.state["wifi_recon_advisory_total"] = 0
    ctx.source("advisory-by-design (on-air Wi-Fi recon needs monitor-mode RF adjacency)")


INTEL_FIELDS = [("Coverage", "wifi_recon_advisory")]


@router.post("/api/wireless/wifi_recon_advisory")
async def wireless_wifi_recon_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="wifi_recon_advisory",
        gather_func=gather, finding_rules=WIFI_RECON_ADVISORY_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
