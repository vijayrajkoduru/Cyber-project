"""wps_pin_audit - audit WPS enablement + Pixie Dust susceptibility on a
target AP (playbook §2 #19).

Runs `reaver -i <iface> -b <bssid> -K 1 -vv -L` in Pixie Dust passive mode
(no actual PIN brute-force). reaver -K performs the offline Pixie Dust
attack against the AP's E-S1/E-S2 nonces during the first WPS exchange;
if the AP is vulnerable the WPS PIN + PSK fall out in <10 minutes. This
probe just checks if the AP advertises WPS + lets reaver collect enough
to flag the vulnerability — actual exploitation is gated behind manual
review.

Customer input:
  ScanRequest.target            = BSSID (MAC) of the target AP
  ScanRequest.options.interface = monitor-mode interface
  ScanRequest.options.channel   = channel (1-14 for 2.4 GHz; reaver only)
  ScanRequest.options.scan_duration = seconds (default 45, capped at 120)
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
from tools._payloads.wps_pin_audit_findings import WPS_PIN_AUDIT_FINDING_RULES

router = APIRouter()
REAVER_BIN = shutil.which("reaver") or "/usr/sbin/reaver"
DEFAULT_DURATION = 45
MAX_DURATION = 120

_REQ_OPTS: contextvars.ContextVar = contextvars.ContextVar("wps_opts", default={})
_BSSID_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


async def gather(ctx: ScanContext):
    opts = _REQ_OPTS.get() or {}
    target = (ctx.host or "").strip()
    iface = (opts.get("interface") or "").strip()
    channel = opts.get("channel")
    duration = int(opts.get("scan_duration") or DEFAULT_DURATION)
    duration = max(10, min(duration, MAX_DURATION))

    if not shutil.which("reaver") and not os.path.exists(REAVER_BIN):
        ctx.state["reaver_binary_missing"] = True
        ctx.state["wps_pin_audit_total"] = 0
        ctx.source("reaver missing")
        return

    if not iface:
        ctx.state["no_monitor_interface"] = True
        ctx.state["wps_pin_audit_total"] = 0
        ctx.source("no interface")
        return

    if not target or not _BSSID_RE.match(target):
        ctx.state["bad_bssid"] = target
        ctx.state["wps_pin_audit_total"] = 0
        ctx.source(f"target '{target}' is not a valid BSSID")
        return

    # Verify iface exists.
    try:
        with open("/proc/net/dev") as f:
            present = any(iface in line.split(":")[0] for line in f.readlines())
    except Exception:
        present = False
    if not present:
        ctx.state["interface_not_present"] = iface
        ctx.state["wps_pin_audit_total"] = 0
        ctx.source(f"{iface} not present")
        return

    cmd = [REAVER_BIN, "-i", iface, "-b", target, "-K", "1", "-vv", "-L", "-N"]
    if channel:
        try:
            cmd += ["-c", str(int(channel))]
        except Exception:
            pass

    stdout_buf = b""
    stderr_buf = b""
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_buf, stderr_buf = await asyncio.wait_for(
                proc.communicate(), timeout=duration
            )
        except asyncio.TimeoutError:
            try: proc.kill()
            except Exception: pass
            try:
                stdout_buf, stderr_buf = await proc.communicate()
            except Exception:
                pass
    except FileNotFoundError:
        ctx.state["reaver_binary_missing"] = True
        ctx.state["wps_pin_audit_total"] = 0
        ctx.source("reaver exec failed")
        return
    except PermissionError:
        ctx.state["reaver_permission_denied"] = True
        ctx.state["wps_pin_audit_total"] = 0
        ctx.source("reaver permission denied")
        return
    except Exception as e:
        ctx.state["reaver_error"] = str(e)[:200]
        ctx.state["wps_pin_audit_total"] = 0
        ctx.source(f"reaver error: {str(e)[:80]}")
        return

    output = (stdout_buf + b"\n" + stderr_buf).decode("utf-8", "replace")
    _summarize_reaver(ctx, output, target)


def _summarize_reaver(ctx: ScanContext, output: str, bssid: str):
    """Parse reaver -K -vv output for WPS state + Pixie Dust readiness."""
    state = {
        "wps_enabled": None,
        "wps_locked": None,
        "ap_manufacturer": "",
        "ap_model_name": "",
        "ap_serial": "",
        "pixie_dust_indicator": False,
        "pin_recovered": "",
        "psk_recovered": "",
        "raw_lines": 0,
    }
    state["raw_lines"] = output.count("\n")
    o = output

    if re.search(r"WPS.*locked", o, re.I):
        state["wps_locked"] = True
    if re.search(r"WPS.*\b(not locked|unlocked)", o, re.I):
        state["wps_locked"] = False
    if re.search(r"Sending\s+M1\b", o) or re.search(r"Received\s+M1\b", o):
        state["wps_enabled"] = True
    if re.search(r"WPS.*disabled", o, re.I):
        state["wps_enabled"] = False
    if re.search(r"Pixie[- ]?Dust", o, re.I) or "WPS pin:" in o or "pixiewps" in o:
        state["pixie_dust_indicator"] = True

    mfr = re.search(r"Manufacturer\s*:\s*(.+)", o)
    if mfr: state["ap_manufacturer"] = mfr.group(1).strip()[:80]
    model = re.search(r"Model Name\s*:\s*(.+)", o)
    if model: state["ap_model_name"] = model.group(1).strip()[:80]
    serial = re.search(r"Serial Number\s*:\s*(.+)", o)
    if serial: state["ap_serial"] = serial.group(1).strip()[:60]

    pin = re.search(r"WPS\s+PIN\s*:\s*'?(\d{4,8})'?", o)
    if pin: state["pin_recovered"] = pin.group(1)
    psk = re.search(r"WPA\s+PSK\s*:\s*'([^']+)'", o)
    if psk: state["psk_recovered"] = "REDACTED-len" + str(len(psk.group(1)))

    ctx.state["wps_audit"] = state
    ctx.state["bssid"] = bssid
    ctx.state["wps_pin_audit_total"] = sum([
        1 if state.get("wps_enabled") else 0,
        1 if state.get("pin_recovered") else 0,
    ])
    ctx.source(f"reaver -K output parsed; wps_enabled={state.get('wps_enabled')} "
               f"locked={state.get('wps_locked')} pixie={state.get('pixie_dust_indicator')}")


INTEL_FIELDS = [("BSSID", "bssid"),
                ("WPS audit", "wps_audit")]


@router.post("/api/wireless/wps_pin_audit")
async def wireless_wps_pin_audit(req: ScanRequest, request: Request, _=Depends(verify_scan_quota)):
    try:
        body = await request.json()
    except Exception:
        body = {}
    _REQ_OPTS.set(body.get("options") or {})
    return await run_scanner(host=req.target, tool="wps_pin_audit",
        gather_func=gather, finding_rules=WPS_PIN_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
