"""hardware_interface_advisory - UART / JTAG / SWD hardware debug (playbook §6 #49-#58).

ADVISORY-BY-DESIGN. The §6 techniques — UART pin discovery + baud detection,
JTAGulator/Glasgow pin discovery, OpenOCD JTAG/SWD attach, BusPirate SPI/UART,
manual JTAG protocol RE, SWD chain walking, UART-shell privesc — all require
PHYSICAL POSSESSION of the device plus bench hardware (logic analyser,
JTAGulator, OpenOCD adapter, BusPirate). None can be executed by an external
SaaS against an uploaded firmware blob.

This scanner does NOT fabricate a finding. It does one OPTIONAL real thing:
if a firmware blob is supplied, it greps the bytes for UART/console
configuration hints (`console=ttyS0`, `getty`, `bootargs console=`, JTAG
enable fuses referenced in DTS) and lists them as INFO context — but it never
upgrades that to a graded severity. The technique itself is emitted as an
honest [ADVISORY-BY-DESIGN] INFO so the customer sees it as intentionally
manual / red-team, not a coverage gap.

Customer input: ScanRequest.target = optional path to firmware blob on disk.
"""
from __future__ import annotations
import asyncio
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.hardware_interface_advisory_findings import HARDWARE_INTERFACE_ADVISORY_FINDING_RULES

router = APIRouter()
MAX_BYTES = 48 * 1024 * 1024

CONSOLE_RE = re.compile(rb"console=tty(?:S|AMA|MTD)?\d+[,0-9n]*", re.I)
GETTY_RE = re.compile(rb"(?:/sbin/getty|/bin/login|::respawn:.{0,40}getty)", re.I)
BOOTARGS_RE = re.compile(rb"bootargs\s*=\s*[^\x00\n]{0,200}", re.I)
JTAG_HINT_RE = re.compile(rb"jtag|swd|\bdebug[_\- ]?port\b|tck|tms|tdi|tdo", re.I)

TECHNIQUES = [
    "UART pin discovery (logic analyser / PCBite / oscilloscope)",
    "UART connection + baud auto-detect (3.3V/5V)",
    "JTAGulator / Glasgow pin discovery",
    "OpenOCD JTAG/SWD interface attach",
    "BusPirate UART/SPI bridging",
    "Manual JTAG protocol reverse-engineering",
    "Manual SWD chain walking",
    "UART root-shell privesc",
]


def _scan(path: Path):
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_BYTES)
    except OSError:
        return {}
    out = {}
    cons = CONSOLE_RE.findall(data)
    if cons:
        out["console_lines"] = sorted({c.decode("ascii", "replace")[:80] for c in cons})[:8]
    if GETTY_RE.search(data):
        out["serial_getty"] = True
    bargs = BOOTARGS_RE.findall(data)
    if bargs:
        out["bootargs"] = [b.decode("ascii", "replace")[:160] for b in bargs[:4]]
    if JTAG_HINT_RE.search(data):
        out["jtag_swd_strings"] = True
    return out


async def gather(ctx: ScanContext):
    ctx.state["hw_iface_techniques"] = TECHNIQUES
    ctx.state["hw_iface_advisory"] = True

    target = ctx.host
    if target and Path(target).is_file():
        hints = await asyncio.get_event_loop().run_in_executor(None, _scan, Path(target))
        if hints.get("console_lines"):
            ctx.state["hw_console_lines"] = hints["console_lines"]
        if hints.get("serial_getty"):
            ctx.state["hw_serial_getty"] = True
        if hints.get("bootargs"):
            ctx.state["hw_bootargs"] = hints["bootargs"]
        if hints.get("jtag_swd_strings"):
            ctx.state["hw_jtag_swd_strings"] = True

    # total is informational only; advisory rule always emits INFO
    ctx.state["hardware_interface_advisory_total"] = 0
    ctx.source("advisory-by-design (physical hardware access required)")


INTEL_FIELDS = [("Hardware techniques (manual)", "hw_iface_techniques"),
                ("Serial console config",        "hw_console_lines"),
                ("Serial getty/login present",   "hw_serial_getty"),
                ("Kernel bootargs",              "hw_bootargs"),
                ("JTAG/SWD strings present",      "hw_jtag_swd_strings")]


@router.post("/api/firmware/hardware_interface_advisory")
async def firmware_hardware_interface_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="hardware_interface_advisory",
        gather_func=gather, finding_rules=HARDWARE_INTERFACE_ADVISORY_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
