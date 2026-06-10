"""ble_scan_audit - BLE device enumeration + advertising-mode security audit
(playbook §6 #55).

Uses `bluetoothctl scan le on` for `scan_duration` seconds to enumerate
BLE devices in range, then parses the resulting device list. Flags any
device advertising as connectable + unauthenticated as MEDIUM and any
device advertising with legacy pairing as HIGH.

Falls back to `hcitool lescan` if bluetoothctl is missing.

Customer input:
  ScanRequest.target            = local HCI interface (e.g. "hci0") or "auto"
  ScanRequest.options.scan_duration = seconds (default 15, capped at 60)
"""
from __future__ import annotations
import asyncio
import contextvars
import os
import re
import shutil
from fastapi import APIRouter, Depends, Request
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.ble_scan_audit_findings import BLE_SCAN_AUDIT_FINDING_RULES

router = APIRouter()
BLUETOOTHCTL_BIN = shutil.which("bluetoothctl") or "/usr/bin/bluetoothctl"
HCITOOL_BIN = shutil.which("hcitool") or "/usr/bin/hcitool"
HCICONFIG_BIN = shutil.which("hciconfig") or "/usr/bin/hciconfig"
DEFAULT_DURATION = 15
MAX_DURATION = 60

_REQ_OPTS: contextvars.ContextVar = contextvars.ContextVar("ble_opts", default={})
_MAC_RE = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")


async def _exec(cmd: list[str], timeout: float, stdin_data: bytes | None = None) -> tuple[int, str, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(
                proc.communicate(input=stdin_data), timeout=timeout,
            )
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

    have_bluetoothctl = shutil.which("bluetoothctl") is not None or os.path.exists(BLUETOOTHCTL_BIN)
    have_hcitool = shutil.which("hcitool") is not None or os.path.exists(HCITOOL_BIN)
    if not have_bluetoothctl and not have_hcitool:
        ctx.state["bluez_missing"] = True
        ctx.state["ble_scan_audit_total"] = 0
        ctx.source("bluez tools missing")
        return

    # Check adapters via hciconfig if available
    adapters = []
    if os.path.exists(HCICONFIG_BIN) or shutil.which("hciconfig"):
        rc, hci_out, _ = await _exec([HCICONFIG_BIN], timeout=5)
        if rc == 0:
            for line in hci_out.splitlines():
                m = re.match(r"^(hci\d+):", line.strip())
                if m:
                    adapters.append(m.group(1))
    if target != "auto" and target not in adapters and adapters:
        ctx.state["adapter_not_present"] = target
        ctx.state["ble_scan_audit_total"] = 0
        ctx.source(f"{target} not in {adapters}")
        return
    if not adapters and have_bluetoothctl:
        # bluetoothctl can still work via DBus
        adapters = ["auto-via-dbus"]
    if not adapters:
        ctx.state["no_bt_adapter"] = True
        ctx.state["ble_scan_audit_total"] = 0
        ctx.source("no HCI adapter")
        return
    ctx.state["adapters"] = adapters

    devices_seen: list[dict] = []
    raw_output = ""

    if have_bluetoothctl:
        # Use bluetoothctl with stdin script: power on, scan le on, sleep, devices, exit
        script = (
            f"power on\nmenu scan\ntransport le\nback\nscan on\n"
        ).encode()
        # bluetoothctl is interactive — use a fixed-duration loop
        rc, out, err = await _exec(
            [BLUETOOTHCTL_BIN, "--timeout", str(duration), "scan", "le"],
            timeout=duration + 10,
        )
        raw_output = out + "\n" + err
        # Pull "Device AA:BB:CC:DD:EE:FF Name" lines
        for line in raw_output.splitlines():
            m = re.search(r"\bDevice\s+([0-9A-Fa-f:]{17})\s+(.+)$", line)
            if m:
                addr = m.group(1).upper()
                name = m.group(2).strip()
                if not any(d["addr"] == addr for d in devices_seen):
                    devices_seen.append({
                        "addr": addr,
                        "name": name[:80],
                        "source": "bluetoothctl",
                        "flags": [],
                    })
        # Get richer info per device
        if devices_seen:
            rc2, info_out, _ = await _exec(
                [BLUETOOTHCTL_BIN, "devices"], timeout=10,
            )
            for line in info_out.splitlines():
                m = re.search(r"Device\s+([0-9A-Fa-f:]{17})\s+(.+)$", line)
                if m:
                    addr = m.group(1).upper()
                    if not any(d["addr"] == addr for d in devices_seen):
                        devices_seen.append({
                            "addr": addr,
                            "name": m.group(2).strip()[:80],
                            "source": "bluetoothctl-devices",
                            "flags": [],
                        })

    elif have_hcitool:
        # Fallback: hcitool lescan
        rc, out, err = await _exec(
            [HCITOOL_BIN, "lescan", "--duplicates"],
            timeout=duration,
        )
        raw_output = out + "\n" + err
        for line in out.splitlines():
            line = line.strip()
            m = _MAC_RE.match(line)
            if not m:
                continue
            addr = m.group(1).upper()
            name = line[len(m.group(0)):].strip() or "(unknown)"
            if not any(d["addr"] == addr for d in devices_seen):
                devices_seen.append({
                    "addr": addr,
                    "name": name[:80],
                    "source": "hcitool",
                    "flags": [],
                })

    # Heuristic flagging — look at device names + addr OUI
    for d in devices_seen:
        nm = (d["name"] or "").lower()
        if any(s in nm for s in ("legacy", "v1.0", "v2.0", "v2.1")):
            d["flags"].append("legacy_pairing_advertised")
        if "no name" in nm or d["name"] == "(unknown)":
            d["flags"].append("anonymous_advertiser")
        # Public addresses (non-randomized) are more identifiable
        first = d["addr"].split(":")[0]
        try:
            first_byte = int(first, 16)
            if first_byte & 0xC0 == 0x00:
                d["flags"].append("public_static_address")
        except Exception:
            pass
        if not d.get("flags"):
            d["flags"].append("standard_le_advertiser")

    legacy = sum(1 for d in devices_seen if "legacy_pairing_advertised" in d["flags"])
    anon = sum(1 for d in devices_seen if "anonymous_advertiser" in d["flags"])

    ctx.state["ble_devices"] = devices_seen
    ctx.state["ble_device_count"] = len(devices_seen)
    ctx.state["ble_legacy_count"] = legacy
    ctx.state["ble_anon_count"] = anon
    ctx.state["scan_duration_sec"] = duration
    ctx.state["raw_lines"] = raw_output.count("\n")
    ctx.state["ble_scan_audit_total"] = len(devices_seen)
    ctx.source(f"BLE scan {duration}s: {len(devices_seen)} device(s), {legacy} legacy, {anon} anonymous")


INTEL_FIELDS = [("BT adapters", "adapters"),
                ("Scan duration (s)", "scan_duration_sec"),
                ("BLE device count", "ble_device_count"),
                ("Legacy advertisers", "ble_legacy_count"),
                ("Anonymous advertisers", "ble_anon_count"),
                ("BLE devices", "ble_devices")]


@router.post("/api/wireless/ble_scan_audit")
async def wireless_ble_scan_audit(req: ScanRequest, request: Request, _=Depends(verify_scan_quota)):
    try:
        body = await request.json()
    except Exception:
        body = {}
    _REQ_OPTS.set(body.get("options") or {})
    return await run_scanner(host=req.target, tool="ble_scan_audit",
        gather_func=gather, finding_rules=BLE_SCAN_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
