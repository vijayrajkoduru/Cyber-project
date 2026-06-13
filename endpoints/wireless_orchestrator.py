"""wireless module orchestrator - 802.11 Wi-Fi + Bluetooth audit probes.

Per module_playbooks/18_wireless.md - 8 sections, 84 techniques.

Coverage model (honest VA, zero false positives):
  tier1_wifi:
    - wireless_mgmt_exposure_audit  REAL SaaS-safe probe: detects an
      internet-exposed Wi-Fi AP / WLAN-controller admin plane and fingerprints
      the vendor panel. Grades HIGH/MEDIUM ONLY on a confirmed live signature.
    - wireless_mgmt_tls_audit       REAL SaaS-safe probe: inspects the served
      certificate + negotiated TLS on the exposed mgmt plane (expired / default
      vendor cert / deprecated TLS), all actively confirmed.
    - monitor_mode_capability_audit / wpa_handshake_capture_audit / wps_pin_audit
      hardware-dependent local probes (degrade to INFO without a monitor-mode NIC).
  tier2_bluetooth:
    - ble_scan_audit / bluetooth_classic_pair_audit  passive BT/BLE enumeration
      (degrade to INFO without a BT adapter).
  tier3_advisory (INFO-only, advisory-by-design):
    - wifi_recon_advisory / wpa_active_advisory / wpa3_sae_advisory /
      enterprise_eap_advisory / rogue_ap_advisory / bluetooth_active_advisory /
      nfc_rfid_advisory / cellular_sdr_advisory — the RF / hardware /
      LAN-adjacent / physical-layer technique families that genuinely cannot be
      probed from external SaaS. Each emits [ADVISORY-BY-DESIGN] INFO findings
      (one per playbook technique) with manual/on-agent test guidance. The
      planned playbook severity is documented in remediation text but NEVER
      passed through as a finding severity.

NOTE: the hardware-dependent probes require --privileged + USB adapter
passthrough at runtime; they gracefully return INFO when no hardware is
available, so the module is safe to expose from a hardware-less VPS. The two
mgmt-plane probes work from any host. Full RF coverage requires an agent
deployed on a host with a monitor-mode WiFi NIC + BT adapter on the target LAN.

Concurrency is intentionally LOW (2) — wireless probes contend for the
same physical interface and channel; running them in parallel produces
garbage results.
"""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_parallel, run_module_streaming

router = APIRouter()


WIRELESS_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_wifi": [
        # Real, SaaS-safe remote probes (no RF hardware required):
        ("wireless_mgmt_exposure_audit",  "/api/wireless/wireless_mgmt_exposure_audit"),
        ("wireless_mgmt_tls_audit",       "/api/wireless/wireless_mgmt_tls_audit"),
        # Hardware-dependent local probes (degrade to INFO without a NIC):
        ("monitor_mode_capability_audit", "/api/wireless/monitor_mode_capability_audit"),
        ("wpa_handshake_capture_audit",   "/api/wireless/wpa_handshake_capture_audit"),
        ("wps_pin_audit",                 "/api/wireless/wps_pin_audit"),
        ("hashcat_wpa_audit",             "/api/wireless/hashcat_wpa_audit"),
    ],
    "tier2_bluetooth": [
        ("ble_scan_audit",                 "/api/wireless/ble_scan_audit"),
        ("bluetooth_classic_pair_audit",   "/api/wireless/bluetooth_classic_pair_audit"),
    ],
    # Advisory-by-design tier: RF / hardware / LAN-adjacent technique families
    # that CANNOT be probed from external SaaS. INFO-only, vulnerable:false.
    "tier3_advisory": [
        ("wifi_recon_advisory",            "/api/wireless/wifi_recon_advisory"),
        ("wpa_active_advisory",            "/api/wireless/wpa_active_advisory"),
        ("wpa3_sae_advisory",              "/api/wireless/wpa3_sae_advisory"),
        ("enterprise_eap_advisory",        "/api/wireless/enterprise_eap_advisory"),
        ("rogue_ap_advisory",              "/api/wireless/rogue_ap_advisory"),
        ("bluetooth_active_advisory",      "/api/wireless/bluetooth_active_advisory"),
        ("nfc_rfid_advisory",              "/api/wireless/nfc_rfid_advisory"),
        ("cellular_sdr_advisory",          "/api/wireless/cellular_sdr_advisory"),
    ],
}


def _all_tools():
    out = []
    for tier in WIRELESS_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class WirelessRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 2
    options: Optional[dict] = None


def _resolve(req, request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in WIRELESS_TOOLS_BY_TIER:
                tools.extend(WIRELESS_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    return tools, (req.options or {}), jwt


@router.post("/api/wireless/run_all")
async def wireless_run_all(req: WirelessRunAllRequest, request: Request,
                            _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    # Wireless interfaces don't scale — keep concurrency tight (1-2)
    concurrency = max(1, min(req.concurrency or 2, 2))
    gen = run_module_streaming(target=req.target, tools=tools, module_name="wireless",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt)
    return StreamingResponse(gen, media_type="application/x-ndjson",
        headers={"X-Accel-Buffering": "no",
                  "Cache-Control": "no-store, no-transform",
                  "Connection": "keep-alive"})


@router.post("/api/wireless/run_all_buffered")
async def wireless_run_all_buffered(req: WirelessRunAllRequest, request: Request,
                                     _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 2, 2))
    return await run_module_parallel(target=req.target, tools=tools, module_name="wireless",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt)


@router.get("/api/wireless/run_all/tiers")
async def wireless_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in WIRELESS_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in WIRELESS_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
