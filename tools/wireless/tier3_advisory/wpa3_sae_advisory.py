"""wpa3_sae_advisory - WPA3 / SAE attack-family advisory (playbook §3 #27-34).

ADVISORY-BY-DESIGN. Every WPA3 attack in the playbook (Dragonblood SAE
downgrade, SAE side-channel timing, WPA3->WPA2 transition-mode downgrade,
EasyConnect/DPP abuse, SAE H2E abuse, OWE audit, WPA3-Enterprise SAE-PK)
requires monitor-mode RF capture, on-air frame injection, or LAN adjacency to
the target BSS. None of it is reachable from an external SaaS scanner.

This scanner therefore emits INFO-only findings (one per technique family) with
an [ADVISORY-BY-DESIGN] marker and vulnerable:false. The planned playbook
severity is described in remediation text but NEVER passed through as the
finding severity (zero false positives). For live testing, deploy the VulnusLab
agent on a host with a WPA3/6GHz-capable monitor-mode adapter on the target LAN.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.wpa3_sae_advisory_findings import WPA3_SAE_ADVISORY_FINDING_RULES

router = APIRouter()


async def gather(ctx: ScanContext):
    # Pure advisory: no network I/O. Flag that the technique family is
    # advisory-by-design so the rules emit their INFO findings.
    ctx.state["wpa3_advisory"] = True
    ctx.state["wpa3_sae_advisory_total"] = 0
    ctx.source("advisory-by-design (WPA3/SAE requires monitor-mode RF adjacency)")


INTEL_FIELDS = [("Coverage", "wpa3_advisory")]


@router.post("/api/wireless/wpa3_sae_advisory")
async def wireless_wpa3_sae_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="wpa3_sae_advisory",
        gather_func=gather, finding_rules=WPA3_SAE_ADVISORY_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
