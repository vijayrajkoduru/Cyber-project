"""wireless_mgmt_exposure_audit - detect internet-exposed wireless-infrastructure
management planes (playbook §1 Recon / §5 Rogue-AP context).

This is the ONE wireless technique-family that is genuinely probeable from an
external SaaS scanner WITHOUT any RF hardware or LAN adjacency: the management
plane of Wi-Fi access points and wireless LAN controllers (Cisco WLC / Meraki /
Aruba / UniFi / Ruckus / MikroTik / OpenWrt / TP-Link / Netgear ...). When the
admin web UI, SSH, or vendor management port is reachable from the public
internet, an attacker can target it directly (brute force, default creds, known
CVEs) instead of needing physical proximity.

What it does (detect-only, VA not PT):
  - Resolve the target and TCP-reachability check a small set of well-known
    wireless-management ports (HTTP/HTTPS admin, SSH, Telnet, common controller
    ports). asyncio.open_connection with a short timeout — no payloads sent.
  - For any reachable HTTP/HTTPS admin port, fetch ONLY the landing page and
    fingerprint the response (Server header, page <title>, well-known body
    markers) against a signature table of wireless AP / controller admin panels.
  - Grade a finding (MEDIUM/HIGH) ONLY when an actual wireless-admin signature
    is matched on a live response, AND that surface is internet-reachable. Plain
    "port open" with no wireless signature is reported as POSITIVE/INFO context,
    never as a vulnerability (zero false positives).

Safety:
  - No credentials submitted, no brute force, no exploitation, no DoS.
  - All network I/O wrapped in try/except with short timeouts; on any
    unreachable/error condition the probe returns clean INFO context.

Customer input:
  ScanRequest.target = hostname / IP of the wireless AP or controller mgmt plane.
"""
from __future__ import annotations
import asyncio
import contextvars
import re
import socket
import ssl
from fastapi import APIRouter, Depends, Request
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.wireless_mgmt_exposure_audit_findings import (
    WIRELESS_MGMT_EXPOSURE_AUDIT_FINDING_RULES,
)

router = APIRouter()
CONNECT_TIMEOUT = 4.0
HTTP_TIMEOUT = 6.0

_REQ_OPTS: contextvars.ContextVar = contextvars.ContextVar("wmgmt_opts", default={})

# Ports commonly used by Wi-Fi AP / WLAN-controller management planes.
# (label, port, scheme) — scheme drives the HTTP fingerprint fetch.
_MGMT_PORTS: list[tuple[str, int, str]] = [
    ("http-admin", 80, "http"),
    ("https-admin", 443, "https"),
    ("http-alt-admin", 8080, "http"),
    ("https-alt-admin", 8443, "https"),
    ("unifi-controller", 8443, "https"),
    ("unifi-inform", 8080, "http"),
    ("ssh-mgmt", 22, "tcp"),
    ("telnet-mgmt", 23, "tcp"),
    ("cisco-wlc-https", 443, "https"),
    ("aruba-https", 4343, "https"),
    ("mikrotik-winbox", 8291, "tcp"),
    ("mikrotik-www", 80, "http"),
]

# Wireless-infrastructure admin-panel signatures. A graded finding is emitted
# ONLY when one of these is matched against a LIVE response from the target.
# (vendor, regexes-any-match) — matched case-insensitively against
# Server header + page title + a slice of the body.
_AP_SIGNATURES: list[tuple[str, list[str]]] = [
    ("Ubiquiti UniFi", [r"unifi", r"ubnt", r"ubiquiti"]),
    ("Cisco Wireless LAN Controller", [r"cisco.*controller", r"airespace",
                                        r"wireless lan controller", r"\bwlc\b"]),
    ("Cisco Meraki", [r"meraki"]),
    ("Aruba / HPE Networking", [r"\baruba\b", r"arubaos", r"instant ap",
                                r"clearpass"]),
    ("Ruckus Wireless", [r"ruckus", r"smartzone", r"zonedirector"]),
    ("MikroTik RouterOS", [r"routeros", r"mikrotik", r"winbox"]),
    ("OpenWrt / LuCI", [r"openwrt", r"luci", r"lede project"]),
    ("DD-WRT", [r"dd-wrt"]),
    ("pfSense / OPNsense (WLAN gateway)", [r"pfsense", r"opnsense"]),
    ("TP-Link AP / Omada", [r"tp-link", r"tplink", r"omada", r"archer\b"]),
    ("Netgear AP / WAC", [r"netgear", r"\bwac\d", r"\bwax\d"]),
    ("Mist / Juniper Wireless", [r"\bmist\b", r"juniper.*wireless"]),
]

# GENERIC, low-specificity markers. These strings ("access point", "SSID",
# "wlan settings", ...) appear on countless unrelated pages (docs, blogs,
# product marketing, any router brochure) and are NOT proof that the live
# response is a wireless-admin management plane. A generic-only match is
# reported as INFO context, never as a graded vendor-confirmed exposure.
_GENERIC_AP_MARKERS: list[str] = [
    r"access point", r"wireless settings", r"\bssid\b", r"wlan settings",
    r"wi-?fi setup", r"wpa2?-?(psk|personal|enterprise)",
]

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


async def _tcp_reachable(host: str, port: int) -> bool:
    """Open a TCP connection and immediately close it. No data sent."""
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT
        )
        return True
    except Exception:
        return False
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass


def _http_fetch_blocking(host: str, port: int, scheme: str) -> tuple[int, dict, str]:
    """Fetch ONLY the landing page. Returns (status, headers, body_slice).
    Synchronous (stdlib urllib) — run in a thread by the caller. Never raises."""
    import urllib.request
    import urllib.error
    url = f"{scheme}://{host}:{port}/"
    headers = {"User-Agent": "VulnusLab-Wireless-Audit/1.0"}
    ctx = None
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=ctx) as resp:
            status = getattr(resp, "status", 0) or resp.getcode() or 0
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read(20000).decode("utf-8", "replace")
            return status, hdrs, body
    except urllib.error.HTTPError as e:
        # An auth-gated admin panel commonly returns 401/403 — still useful.
        try:
            hdrs = {k.lower(): v for k, v in (e.headers or {}).items()}
        except Exception:
            hdrs = {}
        body = ""
        try:
            body = e.read(20000).decode("utf-8", "replace")
        except Exception:
            pass
        return e.code, hdrs, body
    except Exception:
        return 0, {}, ""


def _match_ap_signature(server: str, title: str, body: str) -> tuple[str, str]:
    """Return (vendor_label, match_kind).

    match_kind is:
      "vendor"  - matched an EXACT vendor signature (UniFi, Cisco WLC, ...) ->
                  graded exposure (high confidence this is a wireless admin plane)
      "generic" - matched only a low-specificity AP marker ("access point",
                  "SSID", ...) which any page can contain -> INFO context, NOT
                  graded (zero false positives)
      ""        - no match at all
    """
    blob = f"{server} {title} {body}".lower()
    for vendor, patterns in _AP_SIGNATURES:
        for pat in patterns:
            try:
                if re.search(pat, blob, re.I):
                    return vendor, "vendor"
            except Exception:
                continue
    for pat in _GENERIC_AP_MARKERS:
        try:
            if re.search(pat, blob, re.I):
                return "Generic AP marker (unconfirmed)", "generic"
        except Exception:
            continue
    return "", ""


async def gather(ctx: ScanContext):
    raw = (ctx.host or "").strip()
    if not raw:
        ctx.state["no_target"] = True
        ctx.state["wireless_mgmt_exposure_audit_total"] = 0
        ctx.source("no target")
        return

    # Normalize: strip scheme + path if a URL was passed.
    host = raw
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://([^/]+)", raw)
    if m:
        host = m.group(1)
    host = host.split("/")[0].split("?")[0]
    if "@" in host:
        host = host.split("@")[-1]
    # Strip an explicit :port suffix for the per-port loop (IPv6 kept simple).
    if host.count(":") == 1 and not host.startswith("["):
        host = host.split(":")[0]
    host = host.strip("[]")

    # Resolve to confirm the target exists. Failure -> clean INFO, no finding.
    resolved_ip = ""
    try:
        resolved_ip = await asyncio.get_event_loop().run_in_executor(
            None, lambda: socket.gethostbyname(host)
        )
    except Exception:
        ctx.state["resolve_failed"] = host
        ctx.state["wireless_mgmt_exposure_audit_total"] = 0
        ctx.source(f"could not resolve {host}")
        return
    ctx.state["resolved_ip"] = resolved_ip
    ctx.state["target_host"] = host

    # 1) TCP-reachability for each candidate mgmt port (dedup by port).
    checked_ports: dict[int, bool] = {}
    open_ports: list[dict] = []
    for label, port, scheme in _MGMT_PORTS:
        if port in checked_ports:
            reachable = checked_ports[port]
        else:
            reachable = await _tcp_reachable(host, port)
            checked_ports[port] = reachable
        if reachable and not any(p["port"] == port for p in open_ports):
            open_ports.append({"port": port, "scheme": scheme,
                               "label": label, "ap_vendor": ""})
    ctx.state["open_mgmt_ports"] = open_ports
    ctx.state["open_mgmt_port_count"] = len(open_ports)

    if not open_ports:
        ctx.state["no_mgmt_ports_reachable"] = True
        ctx.state["wireless_mgmt_exposure_audit_total"] = 0
        ctx.source(f"{host} ({resolved_ip}): no wireless-mgmt ports reachable")
        return

    # 2) For HTTP/HTTPS ports, fetch the landing page + fingerprint AP/controller.
    ap_admin_hits: list[dict] = []      # EXACT vendor matches -> graded
    generic_marker_hits: list[dict] = []  # generic-only -> INFO context
    plain_web_ports: list[dict] = []
    loop = asyncio.get_event_loop()
    for p in open_ports:
        if p["scheme"] not in ("http", "https"):
            continue
        try:
            status, hdrs, body = await loop.run_in_executor(
                None, _http_fetch_blocking, host, p["port"], p["scheme"]
            )
        except Exception:
            status, hdrs, body = 0, {}, ""
        if status == 0 and not hdrs and not body:
            continue
        server = hdrs.get("server", "") or ""
        wwwauth = hdrs.get("www-authenticate", "") or ""
        tm = _TITLE_RE.search(body or "")
        title = (tm.group(1).strip() if tm else "")[:120]
        vendor, kind = _match_ap_signature(f"{server} {wwwauth}", title, body)
        p["status"] = status
        p["server"] = server[:120]
        p["title"] = title
        url = f"{p['scheme']}://{host}:{p['port']}/"
        if kind == "vendor":
            p["ap_vendor"] = vendor
            ap_admin_hits.append({
                "port": p["port"], "scheme": p["scheme"], "vendor": vendor,
                "status": status, "server": server[:120], "title": title,
                "url": url,
            })
        elif kind == "generic":
            # A generic marker is NOT a confirmed wireless admin panel — record
            # as INFO context only, never as a graded exposure.
            generic_marker_hits.append({
                "port": p["port"], "scheme": p["scheme"],
                "status": status, "server": server[:120], "title": title,
                "url": url,
            })
        else:
            plain_web_ports.append({"port": p["port"], "scheme": p["scheme"],
                                    "status": status, "server": server[:120],
                                    "title": title})

    ctx.state["ap_admin_exposed"] = ap_admin_hits
    ctx.state["ap_admin_exposed_count"] = len(ap_admin_hits)
    ctx.state["generic_ap_markers"] = generic_marker_hits
    ctx.state["generic_ap_marker_count"] = len(generic_marker_hits)
    ctx.state["plain_web_ports"] = plain_web_ports

    # Plaintext mgmt (telnet/ssh) reachable is context, not by itself a vuln —
    # but telnet on a wireless mgmt plane IS a real, verifiable weakness.
    telnet_open = any(p["port"] == 23 for p in open_ports)
    ctx.state["telnet_mgmt_reachable"] = telnet_open

    ctx.state["wireless_mgmt_exposure_audit_total"] = len(ap_admin_hits) + (1 if telnet_open else 0)
    ctx.source(
        f"{host} ({resolved_ip}): {len(open_ports)} mgmt port(s) reachable, "
        f"{len(ap_admin_hits)} confirmed wireless-admin panel(s), "
        f"{len(generic_marker_hits)} generic-marker-only (unconfirmed)"
    )


INTEL_FIELDS = [
    ("Target host", "target_host"),
    ("Resolved IP", "resolved_ip"),
    ("Reachable mgmt ports", "open_mgmt_port_count"),
    ("Open mgmt ports", "open_mgmt_ports"),
    ("Confirmed AP/controller admin panels", "ap_admin_exposed"),
    ("Generic AP markers (unconfirmed)", "generic_ap_markers"),
    ("Other web ports", "plain_web_ports"),
    ("Telnet mgmt reachable", "telnet_mgmt_reachable"),
]


@router.post("/api/wireless/wireless_mgmt_exposure_audit")
async def wireless_wireless_mgmt_exposure_audit(req: ScanRequest, request: Request,
                                                _=Depends(verify_scan_quota)):
    try:
        body = await request.json()
    except Exception:
        body = {}
    _REQ_OPTS.set(body.get("options") or {})
    return await run_scanner(host=req.target, tool="wireless_mgmt_exposure_audit",
        gather_func=gather, finding_rules=WIRELESS_MGMT_EXPOSURE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
