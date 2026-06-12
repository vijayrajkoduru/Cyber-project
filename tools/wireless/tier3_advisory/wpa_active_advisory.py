"""wpa_active_advisory - WEP/WPA/WPA2 ACTIVE attack-family advisory
(playbook §2, the active attacks beyond handshake capture + WPS audit).

ADVISORY-BY-DESIGN. WEP IV collection+crack, deauthentication attack, PMKID
capture, offline PSK crack (hashcat 22000), wifite workflow, KRACK
(CVE-2017-13077), Karma probe-response abuse, Wi-Fi covert channel, OneShot
Pixie Dust, and EAPOL replay all require monitor-mode RF capture and/or active
frame injection adjacent to the target BSS. Deauth/injection are disruptive
active attacks (PT, not VA). The tier1_wifi scanners already do the SAFE
detection (handshake capturability, WPS/Pixie state). This documents the rest.

Emits INFO-only [ADVISORY-BY-DESIGN] findings. Planned severities are in
remediation text only; never the finding severity.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.wpa_active_advisory_findings import WPA_ACTIVE_ADVISORY_FINDING_RULES

router = APIRouter()


async def gather(ctx: ScanContext):
    ctx.state["wpa_active_advisory"] = True
    ctx.state["wpa_active_advisory_total"] = 0
    ctx.source("advisory-by-design (WEP/WPA active attacks need RF injection + adjacency)")


INTEL_FIELDS = [("Coverage", "wpa_active_advisory")]


@router.post("/api/wireless/wpa_active_advisory")
async def wireless_wpa_active_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="wpa_active_advisory",
        gather_func=gather, finding_rules=WPA_ACTIVE_ADVISORY_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
