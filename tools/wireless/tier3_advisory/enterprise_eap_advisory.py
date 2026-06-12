"""enterprise_eap_advisory - Enterprise WiFi (WPA2/3-EAP) attack-family advisory
(playbook §4 #35-44).

ADVISORY-BY-DESIGN. Enterprise EAP attacks (EAP-TLS cert-chain audit, PEAP/TTLS
credential capture via hostapd-wpe, NetNTLMv2/MSCHAPv2 harvesting from RADIUS,
rogue-RADIUS impersonation, EAP downgrade, 802.1X MAC-bypass, SAE-PK) require
standing up a rogue access point / RADIUS endpoint on the target RF and luring
client supplicants — physical proximity + active impersonation. None is
reachable from external SaaS.

Emits INFO-only [ADVISORY-BY-DESIGN] findings (one per technique). Planned
severities are described in remediation text only, never used as the finding
severity (zero false positives).
"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.enterprise_eap_advisory_findings import (
    ENTERPRISE_EAP_ADVISORY_FINDING_RULES,
)

router = APIRouter()


async def gather(ctx: ScanContext):
    ctx.state["enterprise_eap_advisory"] = True
    ctx.state["enterprise_eap_advisory_total"] = 0
    ctx.source("advisory-by-design (enterprise EAP requires rogue-AP/RADIUS RF adjacency)")


INTEL_FIELDS = [("Coverage", "enterprise_eap_advisory")]


@router.post("/api/wireless/enterprise_eap_advisory")
async def wireless_enterprise_eap_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="enterprise_eap_advisory",
        gather_func=gather, finding_rules=ENTERPRISE_EAP_ADVISORY_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
