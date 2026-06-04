"""bluetooth_classic_pair_audit - Bluetooth Classic (BR/EDR) device + pair-mode audit
(playbook §6 #60).

Uses `bluetoothctl scan bredr on` plus `hcitool inq` to enumerate Bluetooth
Classic devices, then `sdptool browse <BDADDR>` (where available) to read
the Service Discovery Protocol records and infer pairing modes. Flags
devices advertising Legacy PIN pairing as HIGH (CVE-2017-0785 BlueBorne
family + BIAS / KNOB on legacy pairing); Just Works pairing as MEDIUM;
Secure Connections Only as POSITIVE.

Customer input:
  ScanRequest.target            = local HCI interface ("hci0") or "auto"
  ScanRequest.options.scan_duration = seconds (default 20, capped at 60)
"""
from __future__ import annotations
import asyncio
import contextvars
import os
import re
import shutil
from fastapi import APIRouter, Depends, Request
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.bluetooth_classic_pair_audit_findings import (
    BLUETOOTH_CLASSIC_PAIR_AUDIT_FINDING_RULES,
)

router = APIRouter()
BLUETOOTHCTL_BIN = shutil.which("bluetoothctl") or "/usr/bin/bluetoothctl"
HCITOOL_BIN = shutil.which("hcitool") or "/usr/bin/hcitool"
HCICONFIG_BIN = shutil.which("hciconfig") or "/usr/bin/hciconfig"
SDPTOOL_BIN = shutil.which("sdptool") or "/usr/bin/sdptool"
DEFAULT_DURATION = 20
MAX_DURATION = 60

_REQ_OPTS: contextvars.ContextVar = contextvars.ContextVar("btc_opts", default={})
_MAC_RE = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")


async def _exec(cmd: list[str], timeout: float) -> tuple[int, str, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return proc.returncode or 0, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")
        except asyncio.TimeoutError:
            try: proc.kill()
            except Exception: pass
            try: out, err = await proc.communicate()
            except Exception: out, err = b"", b""
            return 124, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")
    except Exception as e:
        return 1, "", str(e)


async def gather(ctx: ScanContext):
    opts = _REQ_OPTS.get() or {}
    target = (ctx.host or "").strip() or "auto"
    duration = int(opts.get("scan_duration") or DEFAULT_DURATION)
    duration = max(5, min(duration, MAX_DURATION))

    have_btctl = shutil.which("bluetoothctl") is not None or os.path.exists(BLUETOOTHCTL_BIN)
    have_hcitool = shutil.which("hcitool") is not None or os.path.exists(HCITOOL_BIN)
    have_sdptool = shutil.which("sdptool") is not None or os.path.exists(SDPTOOL_BIN)

    if not have_btctl and not have_hcitool:
        ctx.state["bluez_missing"] = True
        ctx.state["bluetooth_classic_pair_audit_total"] = 0
        ctx.source("bluez tools missing")
        return

    # Enumerate adapters
    adapters = []
    if os.path.exists(HCICONFIG_BIN) or shutil.which("hciconfig"):
        rc, hci_out, _ = await _exec([HCICONFIG_BIN], timeout=5)
        if rc == 0:
            for line in hci_out.splitlines():
                m = re.match(r"^(hci\d+):", line.strip())
                if m:
                    adapters.append(m.group(1))
    if not adapters and have_btctl:
        adapters = ["auto-via-dbus"]
    if not adapters:
        ctx.state["no_bt_adapter"] = True
        ctx.state["bluetooth_classic_pair_audit_total"] = 0
        ctx.source("no HCI adapter")
        return
    if target != "auto" and adapters and target not in adapters and "auto-via-dbus" not in adapters:
        ctx.state["adapter_not_present"] = target
        ctx.state["bluetooth_classic_pair_audit_total"] = 0
        ctx.source(f"{target} not in {adapters}")
        return
    ctx.state["adapters"] = adapters

    devices: list[dict] = []
    raw_output = ""

    # Prefer hcitool inq for BR/EDR (it emits clock + class-of-device).
    if have_hcitool:
        rc, out, err = await _exec(
            [HCITOOL_BIN, "inq"] + (["-i", target] if target != "auto" and target.startswith("hci") else []),
            timeout=duration + 10,
        )
        raw_output = out + "\n" + err
        # Lines look like: "AA:BB:CC:DD:EE:FF  clock offset: 0x0000  class: 0x240414"
        for line in out.splitlines():
            line = line.strip()
            m = _MAC_RE.match(line)
            if not m:
                continue
            addr = m.group(1).upper()
            cod_match = re.search(r"class:\s*0x([0-9A-Fa-f]+)", line)
            cod_hex = cod_match.group(1) if cod_match else ""
            devices.append({
                "addr": addr,
                "cod_hex": cod_hex,
                "device_class": _decode_cod(cod_hex),
                "name": "",
                "services": [],
                "pairing_mode": "unknown",
                "flags": [],
            })
        # Resolve names via hcitool name
        for d in devices:
            rc2, name_out, _ = await _exec(
                [HCITOOL_BIN, "name", d["addr"]],
                timeout=6,
            )
            if rc2 == 0:
                d["name"] = name_out.strip()[:80]

    elif have_btctl:
        rc, out, err = await _exec(
            [BLUETOOTHCTL_BIN, "--timeout", str(duration), "scan", "bredr"],
            timeout=duration + 10,
        )
        raw_output = out + "\n" + err
        for line in out.splitlines():
            m = re.search(r"\bDevice\s+([0-9A-Fa-f:]{17})\s+(.+)$", line)
            if not m:
                continue
            addr = m.group(1).upper()
            if not any(d["addr"] == addr for d in devices):
                devices.append({
                    "addr": addr, "cod_hex": "", "device_class": "",
                    "name": m.group(2).strip()[:80],
                    "services": [], "pairing_mode": "unknown", "flags": [],
                })

    # SDP browse — infer pairing capability per device
    legacy_count, just_works_count, secure_count = 0, 0, 0
    if have_sdptool:
        for d in devices[:10]:  # cap SDP browses to 10 devices for time budget
            rc, sdp_out, _ = await _exec(
                [SDPTOOL_BIN, "browse", "--tree", d["addr"]],
                timeout=12,
            )
            if rc == 0 and sdp_out:
                services = re.findall(r"Service Name:\s*(.+)", sdp_out)
                d["services"] = [x.strip()[:60] for x in services][:8]
                low = sdp_out.lower()
                if "service description: legacy" in low or "pin code" in low:
                    d["pairing_mode"] = "legacy_pin"
                    d["flags"].append("legacy_pin_pairing")
                    legacy_count += 1
                elif "io capability: nosbutton" in low or "no input no output" in low:
                    d["pairing_mode"] = "just_works"
                    d["flags"].append("just_works_pairing")
                    just_works_count += 1
                elif "secure simple pairing" in low or "secure connections" in low:
                    d["pairing_mode"] = "secure_connections"
                    d["flags"].append("secure_connections")
                    secure_count += 1
            # Tag via Class-of-Device when SDP gave nothing
            if d["pairing_mode"] == "unknown" and d.get("device_class"):
                if "Headset" in d["device_class"] or "Audio" in d["device_class"]:
                    d["pairing_mode"] = "likely_legacy_audio"
                    d["flags"].append("likely_legacy_audio")
                    legacy_count += 1

    ctx.state["btc_devices"] = devices
    ctx.state["btc_device_count"] = len(devices)
    ctx.state["btc_legacy_count"] = legacy_count
    ctx.state["btc_just_works_count"] = just_works_count
    ctx.state["btc_secure_count"] = secure_count
    ctx.state["scan_duration_sec"] = duration
    ctx.state["have_sdptool"] = have_sdptool
    ctx.state["raw_lines"] = raw_output.count("\n")
    ctx.state["bluetooth_classic_pair_audit_total"] = (
        legacy_count + just_works_count
    )
    ctx.source(f"BT-Classic scan {duration}s: {len(devices)} device(s), "
               f"{legacy_count} legacy, {just_works_count} just-works, "
               f"{secure_count} secure")


def _decode_cod(cod_hex: str) -> str:
    """Decode the major service / device class from CoD hex."""
    if not cod_hex:
        return ""
    try:
        cod = int(cod_hex, 16)
    except Exception:
        return ""
    # Major Device Class bits 8-12
    major = (cod >> 8) & 0x1F
    table = {
        0x00: "Misc", 0x01: "Computer", 0x02: "Phone", 0x03: "LAN/Network AP",
        0x04: "Audio/Video", 0x05: "Peripheral (HID)", 0x06: "Imaging",
        0x07: "Wearable", 0x08: "Toy", 0x09: "Health",
    }
    return table.get(major, f"Unknown(0x{major:02X})")


INTEL_FIELDS = [("BT adapters", "adapters"),
                ("Scan duration (s)", "scan_duration_sec"),
                ("Device count", "btc_device_count"),
                ("Legacy-pairing devices", "btc_legacy_count"),
                ("Just-Works devices", "btc_just_works_count"),
                ("Secure-Connections devices", "btc_secure_count"),
                ("sdptool available", "have_sdptool"),
                ("BT-Classic devices", "btc_devices")]


@router.post("/api/wireless/bluetooth_classic_pair_audit")
async def wireless_bluetooth_classic_pair_audit(req: ScanRequest, request: Request,
                                                  _=Depends(verify_scan_quota)):
    try:
        body = await request.json()
    except Exception:
        body = {}
    _REQ_OPTS.set(body.get("options") or {})
    return await run_scanner(host=req.target, tool="bluetooth_classic_pair_audit",
        gather_func=gather, finding_rules=BLUETOOTH_CLASSIC_PAIR_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
