"""monitor_mode_capability_audit - probe Wi-Fi adapter monitor-mode support
(playbook §1 #1).

Runs `iw dev` to enumerate wireless interfaces and `iw phy` (or `iw list`)
to inspect each PHY's supported interface modes. A monitor-mode capable
adapter is a prerequisite for nearly every Wi-Fi attack (handshake capture,
deauth, evil twin, KARMA, hcxdumptool PMKID). This probe is detect-only
and never puts an interface into monitor mode.

Customer input: ScanRequest.target = interface name ("wlan0") or "auto"
to use any detected wireless interface.
"""
from __future__ import annotations
import asyncio
import shutil
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.monitor_mode_capability_audit_findings import (
    MONITOR_MODE_CAPABILITY_AUDIT_FINDING_RULES,
)

router = APIRouter()
IW_BIN = shutil.which("iw") or "/sbin/iw"
TIMEOUT = 15


async def _run_iw(*args, timeout=TIMEOUT) -> tuple[int, str, str]:
    """Call `iw <args>` and return (rc, stdout, stderr)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            IW_BIN, *args,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode or 0, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")
    except asyncio.TimeoutError:
        try: proc.kill()
        except Exception: pass
        return 124, "", f"iw {' '.join(args)} timed out after {timeout}s"
    except Exception as e:
        return 1, "", str(e)


def _parse_iw_dev(stdout: str) -> list[dict]:
    """Parse `iw dev` blocks into [{phy, ifname, type, addr}, ...]."""
    interfaces, current = [], None
    current_phy = ""
    for raw in stdout.splitlines():
        line = raw.strip()
        if line.startswith("phy#"):
            current_phy = line
            continue
        if line.startswith("Interface "):
            if current:
                current["phy"] = current_phy
                interfaces.append(current)
            current = {"ifname": line.split(None, 1)[1].strip(), "type": "", "addr": "", "phy": ""}
        elif current is not None:
            if line.startswith("type "):
                current["type"] = line.split(None, 1)[1].strip()
            elif line.startswith("addr "):
                current["addr"] = line.split(None, 1)[1].strip()
    if current:
        current["phy"] = current_phy
        interfaces.append(current)
    return interfaces


def _parse_iw_phy_modes(stdout: str) -> list[str]:
    """Pull the 'Supported interface modes:' list from `iw phy <phy> info`."""
    modes, in_block = [], False
    for raw in stdout.splitlines():
        line = raw.strip()
        if line.startswith("Supported interface modes:"):
            in_block = True
            continue
        if in_block:
            if line.startswith("*"):
                m = line.lstrip("* ").strip()
                if m:
                    modes.append(m)
            else:
                if not line.startswith("*") and line and not line[0].isspace():
                    break
    return modes


async def gather(ctx: ScanContext):
    target = (ctx.host or "").strip()
    if not shutil.which("iw") and not __import__("os").path.exists(IW_BIN):
        ctx.state["iw_binary_missing"] = True
        ctx.state["monitor_mode_capability_audit_total"] = 0
        ctx.source("iw missing")
        return

    rc, dev_out, dev_err = await _run_iw("dev")
    if rc != 0:
        ctx.state["iw_dev_error"] = (dev_err or "iw dev failed")[:200]
        ctx.state["monitor_mode_capability_audit_total"] = 0
        ctx.source(f"iw dev rc={rc}")
        return

    interfaces = _parse_iw_dev(dev_out)
    if not interfaces:
        ctx.state["no_wireless_interface"] = True
        ctx.state["monitor_mode_capability_audit_total"] = 0
        ctx.source("no wireless interfaces found")
        return

    # Filter to the requested interface if not "auto"
    if target and target.lower() not in ("auto", "", "all"):
        interfaces = [i for i in interfaces if i["ifname"] == target]
        if not interfaces:
            ctx.state["requested_interface_missing"] = target
            ctx.state["monitor_mode_capability_audit_total"] = 0
            ctx.source(f"interface {target} not present")
            return

    # For each interface, look up its PHY and parse supported modes
    results, monitor_capable, phys_seen = [], 0, set()
    for iface in interfaces:
        phy = iface.get("phy", "").lstrip("phy#")
        modes = []
        if phy and phy not in phys_seen:
            phys_seen.add(phy)
            rc2, phy_out, _ = await _run_iw("phy", f"phy{phy}", "info")
            if rc2 == 0:
                modes = _parse_iw_phy_modes(phy_out)
        monitor_supported = any("monitor" in m.lower() for m in modes)
        if monitor_supported:
            monitor_capable += 1
        results.append({
            "ifname": iface["ifname"],
            "phy": f"phy{phy}" if phy else "",
            "current_type": iface.get("type", ""),
            "addr": iface.get("addr", ""),
            "supported_modes": modes,
            "monitor_supported": monitor_supported,
        })

    ctx.state["wifi_interfaces"] = results
    ctx.state["interface_count"] = len(results)
    ctx.state["monitor_capable_count"] = monitor_capable
    ctx.state["monitor_mode_capability_audit_total"] = monitor_capable
    ctx.source(f"iw enumerated {len(results)} iface(s); {monitor_capable} monitor-capable")


INTEL_FIELDS = [("Wi-Fi interfaces", "wifi_interfaces"),
                ("Interface count", "interface_count"),
                ("Monitor-capable count", "monitor_capable_count")]


@router.post("/api/wireless/monitor_mode_capability_audit")
async def wireless_monitor_mode_capability_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="monitor_mode_capability_audit",
        gather_func=gather, finding_rules=MONITOR_MODE_CAPABILITY_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
