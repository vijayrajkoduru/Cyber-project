"""wpa_handshake_capture_audit - audit WPA/WPA2 4-way-handshake capturability
(playbook §2 #14).

Runs `airodump-ng` locked to a single channel + BSSID for `scan_duration`
seconds and parses the resulting capture for an EAPOL handshake. If a
handshake is captured the AP's PSK is offline-crackable with hashcat
mode 22000 — the finding severity depends on whether the customer's
PSK passes a basic rockyou-style word check (out of scope here; we
just report the capture).

Customer input:
  ScanRequest.target            = ESSID or BSSID (passed to airodump --essid / --bssid)
  ScanRequest.options.channel   = int channel (1-14 / 36-165)
  ScanRequest.options.interface = monitor-mode interface (e.g. "wlan0mon")
  ScanRequest.options.scan_duration = seconds (default 30, capped at 120)
"""
from __future__ import annotations
import asyncio
import os
import re
import shutil
import tempfile
from fastapi import APIRouter, Depends, Request
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.wpa_handshake_capture_audit_findings import (
    WPA_HANDSHAKE_CAPTURE_AUDIT_FINDING_RULES,
)

router = APIRouter()
AIRODUMP_BIN = shutil.which("airodump-ng") or "/usr/sbin/airodump-ng"
DEFAULT_DURATION = 30
MAX_DURATION = 120


# Carry ScanRequest.options into gather() via a context-var.
import contextvars
_REQ_OPTS: contextvars.ContextVar = contextvars.ContextVar("wpa_opts", default={})


_BSSID_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def _is_bssid(s: str) -> bool:
    return bool(_BSSID_RE.match(s or ""))


async def gather(ctx: ScanContext):
    opts = _REQ_OPTS.get() or {}
    target = (ctx.host or "").strip()
    iface = (opts.get("interface") or "").strip()
    channel = opts.get("channel")
    duration = int(opts.get("scan_duration") or DEFAULT_DURATION)
    duration = max(5, min(duration, MAX_DURATION))

    if not shutil.which("airodump-ng") and not os.path.exists(AIRODUMP_BIN):
        ctx.state["airodump_binary_missing"] = True
        ctx.state["wpa_handshake_capture_audit_total"] = 0
        ctx.source("airodump-ng missing")
        return

    if not iface:
        ctx.state["no_monitor_interface"] = True
        ctx.state["wpa_handshake_capture_audit_total"] = 0
        ctx.source("no interface provided")
        return

    # Sanity: ensure interface actually exists on this host.
    try:
        with open("/proc/net/dev") as f:
            present = any(iface in line.split(":")[0] for line in f.readlines())
    except Exception:
        present = False
    if not present:
        ctx.state["interface_not_present"] = iface
        ctx.state["wpa_handshake_capture_audit_total"] = 0
        ctx.source(f"{iface} not present")
        return

    if not target:
        ctx.state["wpa_handshake_capture_audit_total"] = 0
        ctx.source("no target")
        return

    tmp_dir = tempfile.mkdtemp(prefix="vlforge_airodump_")
    prefix = os.path.join(tmp_dir, "cap")
    cmd = [AIRODUMP_BIN, "--output-format", "pcap,csv", "-w", prefix, "--write-interval", "5"]
    if channel:
        try:
            cmd += ["-c", str(int(channel))]
        except Exception:
            pass
    if _is_bssid(target):
        cmd += ["--bssid", target]
    else:
        cmd += ["--essid", target]
    cmd.append(iface)

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=duration)
        except asyncio.TimeoutError:
            try: proc.kill()
            except Exception: pass
            try: await proc.wait()
            except Exception: pass
        # Stop airodump even if it didn't self-exit (it normally runs forever).
        try: proc.terminate()
        except Exception: pass
    except FileNotFoundError:
        ctx.state["airodump_binary_missing"] = True
        ctx.state["wpa_handshake_capture_audit_total"] = 0
        ctx.source("airodump-ng exec failed")
        _cleanup_tmpdir(tmp_dir)
        return
    except PermissionError:
        ctx.state["airodump_permission_denied"] = True
        ctx.state["wpa_handshake_capture_audit_total"] = 0
        ctx.source("airodump needs root + monitor iface")
        _cleanup_tmpdir(tmp_dir)
        return
    except Exception as e:
        ctx.state["airodump_error"] = str(e)[:200]
        ctx.state["wpa_handshake_capture_audit_total"] = 0
        ctx.source(f"airodump error: {str(e)[:80]}")
        _cleanup_tmpdir(tmp_dir)
        return

    # Look for the .cap file
    cap_path = None
    for f in os.listdir(tmp_dir):
        if f.startswith("cap") and (f.endswith(".cap") or f.endswith(".pcap")):
            cap_path = os.path.join(tmp_dir, f)
            break

    handshake_present = False
    eapol_packets = 0
    aps_seen, clients_seen = 0, 0

    if cap_path and os.path.exists(cap_path):
        eapol_packets = _count_eapol(cap_path)
        handshake_present = eapol_packets >= 4
        ctx.state["capture_bytes"] = os.path.getsize(cap_path)

    # Parse the CSV for AP+client counts
    csv_path = None
    for f in os.listdir(tmp_dir):
        if f.startswith("cap") and f.endswith(".csv"):
            csv_path = os.path.join(tmp_dir, f)
            break
    if csv_path:
        aps_seen, clients_seen = _parse_airodump_csv(csv_path)

    ctx.state["handshake_captured"] = handshake_present
    ctx.state["eapol_packets"] = eapol_packets
    ctx.state["aps_observed"] = aps_seen
    ctx.state["clients_observed"] = clients_seen
    ctx.state["scan_duration_sec"] = duration
    ctx.state["target_label"] = target
    ctx.state["wpa_handshake_capture_audit_total"] = 1 if handshake_present else 0
    ctx.source(f"airodump captured {eapol_packets} EAPOL pkt(s) in {duration}s")

    _cleanup_tmpdir(tmp_dir)


def _cleanup_tmpdir(tmp_dir: str) -> None:
    try:
        for f in os.listdir(tmp_dir):
            try: os.unlink(os.path.join(tmp_dir, f))
            except Exception: pass
        os.rmdir(tmp_dir)
    except Exception:
        pass


def _count_eapol(cap_path: str) -> int:
    """Count EAPOL frames in the pcap using tshark if available, else
    a naive byte-pattern check for ethertype 0x888E."""
    tshark = shutil.which("tshark")
    if tshark:
        try:
            import subprocess
            r = subprocess.run([tshark, "-r", cap_path, "-Y", "eapol", "-T", "fields",
                                "-e", "frame.number"],
                               capture_output=True, text=True, timeout=20)
            return len([ln for ln in r.stdout.splitlines() if ln.strip()])
        except Exception:
            pass
    # Fallback: count occurrences of EAPOL ethertype bytes.
    try:
        with open(cap_path, "rb") as f:
            data = f.read()
        return data.count(b"\x88\x8e")
    except Exception:
        return 0


def _parse_airodump_csv(csv_path: str) -> tuple[int, int]:
    aps, clients = 0, 0
    try:
        with open(csv_path) as f:
            content = f.read()
    except Exception:
        return 0, 0
    in_clients = False
    for raw in content.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.lower().startswith("station mac"):
            in_clients = True
            continue
        if line.lower().startswith("bssid"):
            continue
        if "," in line:
            if in_clients:
                clients += 1
            else:
                aps += 1
    return aps, clients


INTEL_FIELDS = [("Target", "target_label"),
                ("Scan duration (s)", "scan_duration_sec"),
                ("APs observed", "aps_observed"),
                ("Clients observed", "clients_observed"),
                ("EAPOL packets", "eapol_packets"),
                ("Handshake captured", "handshake_captured"),
                ("Capture file size (B)", "capture_bytes")]


@router.post("/api/wireless/wpa_handshake_capture_audit")
async def wireless_wpa_handshake_capture_audit(
    req: ScanRequest, request: Request, _=Depends(verify_scan_quota)
):
    # Stash request options for gather()
    try:
        body = await request.json()
    except Exception:
        body = {}
    opts = body.get("options") or {}
    _REQ_OPTS.set(opts)
    return await run_scanner(host=req.target, tool="wpa_handshake_capture_audit",
        gather_func=gather, finding_rules=WPA_HANDSHAKE_CAPTURE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
