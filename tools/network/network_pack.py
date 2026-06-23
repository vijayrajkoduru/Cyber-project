"""§16 Network Attacks — 67 endpoints per 16_network.md.
8 sections: port/service enum, LAN L2, MITM, DoS, sniffing, DNS attacks,
IPv6, protocol fuzzing.

VL-FORGE upgrade 2026-05-30: tier1 (Port & Service Enumeration, 14 endpoints)
upgraded from advisory to LIVE PROBES. Other tiers correctly remain
advisory (LAN/MITM/sniffing require local network access, DoS/fuzzing
are ethical-not-probe, IPv6 needs IPv6 routing).
"""
import json
import re
import shutil
import socket
import asyncio
import subprocess
import urllib.request
import urllib.error
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from tools._pack_common import (
    make_advisory_router, _adv_response, _advisory_by_design_response,
)
from tools._shared import wrap_finding


def _run_bin(cmd, timeout_s=60):
    """Uniform subprocess wrapper. Returns (exit_code, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout_s, check=False)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as e:
        return 124, e.stdout or "", e.stderr or "timeout"
    except FileNotFoundError:
        return 127, "", f"{cmd[0]} not found"
    except Exception as e:
        return 1, "", f"{type(e).__name__}: {str(e)[:200]}"


def _host(target: str) -> str:
    s = target.split("://", 1)[-1].split("/")[0].split(":")[0]
    return s.strip().lower() or target


def _resolve(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return ""


def _tcp_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def _tcp_banner(host: str, port: int, timeout: float = 2.0) -> str:
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) != 0:
                return ""
            try:
                return s.recv(256).decode("utf-8", errors="ignore").strip()
            except Exception:
                return ""
    except Exception:
        return ""


def _probe_database_services(ip: str, timeout: float = 2.5) -> list:
    """Protocol-confirm a database service rather than assuming it from the port
    number. Returns [{"port","service","evidence"}] for each port that actually
    speaks the expected wire protocol. A port being open is NOT enough — the
    handshake/response must match (zero-FP). Covers MySQL/MariaDB, PostgreSQL,
    Redis."""
    confirmed = []

    # ── 3306 MySQL/MariaDB: server sends a handshake greeting on connect ──
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, 3306)) == 0:
                greet = s.recv(256)
                # Greeting: 3-byte len + seq(0x00) + protocol_version(0x0a) then
                # NUL-terminated server version string. Validate the framing.
                if (len(greet) >= 6 and greet[3] == 0x00 and greet[4] == 0x0a):
                    ver = greet[5:].split(b"\x00", 1)[0].decode("latin-1", "ignore")
                    confirmed.append({"port": 3306, "service": "MySQL/MariaDB",
                                      "evidence": f"protocol-10 handshake, version {ver[:40] or '?'}"})
                elif b"mysql" in greet.lower() or b"mariadb" in greet.lower():
                    confirmed.append({"port": 3306, "service": "MySQL/MariaDB",
                                      "evidence": "handshake banner names MySQL/MariaDB"})
    except Exception:
        pass

    # ── 5432 PostgreSQL: answer a startup packet with 'R'(auth)/'E'(error) ──
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, 5432)) == 0:
                # StartupMessage: int32 length, int32 protocol 196608, "user\0probe\0\0"
                body = b"\x00\x03\x00\x00user\x00vl_probe\x00\x00"
                pkt = (len(body) + 4).to_bytes(4, "big") + body
                s.sendall(pkt)
                resp = s.recv(64)
                # First byte 'R' = AuthenticationRequest, 'E' = ErrorResponse —
                # both PROVE a Postgres backend (vs random TCP service).
                if resp and resp[:1] in (b"R", b"E"):
                    confirmed.append({"port": 5432, "service": "PostgreSQL",
                                      "evidence": f"startup answered with '{resp[:1].decode()}' message"})
    except Exception:
        pass

    # ── 6379 Redis: RESP — replies to PING with +PONG or -ERR/-NOAUTH ──
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, 6379)) == 0:
                s.sendall(b"PING\r\n")
                resp = s.recv(128)
                low = resp.lower()
                # RESP frames start +/-/:/$/*; PONG or an auth-required error proves Redis.
                if resp[:1] in (b"+", b"-", b":", b"$", b"*") and (
                        b"pong" in low or b"noauth" in low or b"err" in low or
                        b"wrongpass" in low or b"operation not permitted" in low):
                    confirmed.append({"port": 6379, "service": "Redis",
                                      "evidence": f"RESP reply to PING: {resp[:40].decode('latin-1','ignore').strip()}"})
    except Exception:
        pass

    return confirmed


def _scan_ports(host: str, ports: list, timeout: float = 1.0) -> dict:
    """Concurrent TCP connect scan. Returns {port: True/False}."""
    out = {}
    with ThreadPoolExecutor(max_workers=32) as ex:
        futs = {ex.submit(_tcp_open, host, p, timeout): p for p in ports}
        for fut, p in futs.items():
            try:
                out[p] = fut.result(timeout=timeout + 1)
            except Exception:
                out[p] = False
    return out


# ─── CDN / cloud-edge awareness (mirrors tools/webapp/portscan.py) ───
# A host behind Cloudflare / Akamai / Fastly / a cloud LB shows many "open"
# edge ports that belong to the SHARED CDN edge, NOT the customer origin.
# Those ports are not the customer's exposure and must never be graded.
# Each entry: cdn-name -> list of lowercased regexes; ANY match on the
# lowercased HTTP status-line + headers PROVES we reached that CDN edge.
_CDN_SIGNATURES = {
    "cloudflare": [r"server:\s*cloudflare", r"\bcf-ray:", r"\bcf-cache-status:",
                   r"\b__cfduid", r"\bcf-request-id:"],
    "akamai":     [r"server:\s*akamaighost", r"\bx-akamai", r"\bakamai",
                   r"\bx-cache:\s*tcp_(hit|miss)\b.*akamai"],
    "fastly":     [r"server:\s*fastly", r"x-served-by:\s*cache-", r"\bx-fastly",
                   r"\bfastly-"],
    "cloudfront": [r"server:\s*cloudfront", r"\bx-amz-cf-id:", r"\bx-amz-cf-pop:",
                   r"via:\s*[^\n]*cloudfront"],
    "azure-edge": [r"\bx-azure-ref:", r"server:\s*ecacc", r"\bx-msedge-ref:"],
    "google":     [r"server:\s*gws", r"\bvia:\s*1\.1 google", r"server:\s*gfe"],
}


def _http_head_headers(ip: str, host: str, port: int, tls: bool,
                       timeout: float = 4.0) -> str:
    """Fetch the status line + response headers over HTTP(S) and return them
    lowercased (header block only). Returns "" on any connection/TLS error."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except Exception:
        return ""
    try:
        if tls:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            try:
                sock = ctx.wrap_socket(sock, server_hostname=host)
            except Exception:
                try:
                    sock.close()
                except Exception:
                    pass
                return ""
        sock.settimeout(timeout)
        req = (b"GET / HTTP/1.1\r\nHost: " + host.encode() +
               b"\r\nUser-Agent: VulnusLab-NetScan\r\nAccept: */*\r\n"
               b"Connection: close\r\n\r\n")
        sock.sendall(req)
        buf = b""
        # Only the header block is needed for CDN signatures (~first 8KB).
        while len(buf) < 8192:
            try:
                chunk = sock.recv(2048)
            except Exception:
                break
            if not chunk:
                break
            buf += chunk
            if b"\r\n\r\n" in buf:
                break
        head = buf.split(b"\r\n\r\n", 1)[0]
        return head.decode("utf-8", errors="replace").lower()
    except Exception:
        return ""
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _detect_cdn(host: str, ip: str) -> str:
    """Return the CDN/cloud-edge name if the host's web response PROVES a known
    edge (Cloudflare / Akamai / Fastly / CloudFront / Azure / Google), else "".

    Probes 443 (TLS) then 80 — a confirmed CDN edge means any open-port COUNT is
    the CDN's, not the customer origin, so it must not be graded.
    """
    for port, tls in ((443, True), (80, False)):
        head = _http_head_headers(ip, host, port, tls)
        if not head:
            continue
        for cdn, pats in _CDN_SIGNATURES.items():
            for pat in pats:
                try:
                    if re.search(pat, head):
                        return cdn
                except re.error:
                    continue
    return ""


def _wrap(slug, target, title, sev, cvss, evidence, remed=""):
    return _adv_response(slug, target, title, sev, cvss,
                          cwe="CWE-200",
                          remediation=remed or "Restrict exposed ports to admin VLAN; close non-essential services.",
                          evidence=evidence)


# ─── LIVE PROBES for tier1 Port & Service Enumeration ───

TOP_TCP_PORTS = [21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,465,
                  587,631,636,873,993,995,1080,1433,1521,1723,2049,2222,
                  3306,3389,5432,5900,5985,5986,6379,7001,8000,8080,8443,
                  9000,9200,9300,9418,11211,27017]

def _probe_nmap_syn_scan(target, req):
    """nmap-equivalent TCP connect scan on top 45 ports."""
    host = _host(target); ip = _resolve(host)
    if not ip:
        return _adv_response("nmap_syn_scan", target, f"DNS resolution failed for {host}",
                              "INFO", "0.0", evidence=f"Could not resolve {host}")
    results = _scan_ports(ip, TOP_TCP_PORTS, timeout=1.0)
    opens = sorted([p for p, o in results.items() if o])
    cdn = _detect_cdn(host, ip)
    findings = []
    if opens and cdn:
        # CDN/cloud-edge fronted: the open ports belong to the SHARED edge, not
        # the customer origin. Never graded — INFO with a CDN note (zero-FP).
        findings.append(wrap_finding(
            f"{len(opens)} open ports observed on {host} ({ip}) are CDN edge ports, not origin",
            "INFO", cvss="0.0", cwe="CWE-200",
            remediation=f"Host fronted by {cdn}; these ports terminate at the shared CDN edge, "
                        "not your origin. Audit exposure at the origin host directly.",
            evidence_marker=f"CDN edge: {cdn}; edge ports: {', '.join(str(p) for p in opens)}"))
    elif opens:
        # Not CDN-fronted: a raw open-port COUNT is NOT proof of a vulnerability.
        # Reporting that ports are open is INFO; cap any count-driven concern at
        # LOW (a wide footprint warrants review, but is not itself a finding).
        sev = "INFO" if len(opens) <= 5 else "LOW"
        findings.append(wrap_finding(
            f"Live TCP port scan — {len(opens)} open ports on {host} ({ip})",
            sev, cvss="0.0" if sev == "INFO" else "3.1",
            cwe="CWE-200",
            remediation="Open ports alone are not a vulnerability. Confirm each exposed service "
                        "is intended and access-controlled; firewall non-essential services.",
            evidence_marker=f"Open: {', '.join(str(p) for p in opens)}"))
    top_sev = findings[0].get("severity") if findings else "INFO"
    return {"tool":"nmap_syn_scan","target":target,"scan_time":0,
            "vulnerable": False,
            "severity": top_sev,
            "findings": findings or [wrap_finding(f"No top-45 TCP ports open on {host}",
                "POSITIVE", cvss="0.0", cwe="N/A", remediation="Continue least-exposure posture.",
                evidence_marker=f"Scanned {len(TOP_TCP_PORTS)} ports — all closed")],
            "tests_performed": len(TOP_TCP_PORTS),
            "tests_summary": f"TCP connect scan of {len(TOP_TCP_PORTS)} ports on {host}",
            "raw_data": {"open_ports": opens, "ip": ip, "cdn": cdn or None}}

def _probe_nmap_udp_scan(target, req):
    """UDP probe — limited to DNS/NTP/SNMP/SSDP common UDP."""
    host = _host(target); ip = _resolve(host)
    if not ip:
        return _adv_response("nmap_udp_scan", target, "DNS resolution failed",
                              "INFO", "0.0", evidence=host)
    # Service-specific UDP probes. A bare datagram reply (ICMP noise / a
    # firewall's stateless echo / an unrelated service) is NOT proof a port is
    # open. We send a PROTOCOL-CORRECT request and only count the port "open"
    # when the reply VALIDATES against that protocol's response shape (zero-FP).
    # ports without a known probe are probed-but-only-confirmable on a valid reply.
    _DNS_PROBE = (bytes([0x13, 0x37, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00]) + bytes([6]) + b"google" +
                  bytes([3]) + b"com" + bytes([0, 0, 1, 0, 1]))
    # NTP v3 client mode-3 request (mode/version in first byte = 0x1b).
    _NTP_PROBE = b"\x1b" + b"\x00" * 47
    # SNMPv2c GetRequest for sysDescr.0 (community "public").
    _SNMP_PROBE = bytes.fromhex(
        "302902010104067075626c6963a01c0204"
        "1337133702010002010030"
        "0e300c06082b060102010101000500")

    def _valid_dns(req_bytes, resp):
        # XID must echo (bytes 0-1) and QR bit set (response).
        return (len(resp) >= 4 and resp[0] == req_bytes[0] and
                resp[1] == req_bytes[1] and (resp[2] & 0x80) == 0x80)

    def _valid_ntp(resp):
        # NTP reply: server mode (4) in low 3 bits; payload >= 48 bytes.
        return len(resp) >= 48 and (resp[0] & 0x07) == 4

    def _valid_snmp(resp):
        # SNMP message is an ASN.1 SEQUENCE (0x30) carrying INTEGER version.
        return len(resp) >= 2 and resp[0] == 0x30

    # (port, probe-bytes, validator) — only these carry a protocol validator.
    _UDP_PROBES = [
        (53, _DNS_PROBE, lambda r: _valid_dns(_DNS_PROBE, r)),
        (5353, _DNS_PROBE, lambda r: _valid_dns(_DNS_PROBE, r)),  # mDNS
        (123, _NTP_PROBE, _valid_ntp),
        (161, _SNMP_PROBE, _valid_snmp),
    ]
    other_ports = [67, 68, 137, 500, 514, 520, 1900, 4500]
    udp_ports = [p for p, _, _ in _UDP_PROBES] + other_ports
    confirmed_open = 0       # protocol-valid reply received (real service)
    open_or_filtered = 0     # no reply / unvalidated reply — cannot be confirmed
    confirmed_ports = []
    for port, probe, validator in _UDP_PROBES:
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
                s.settimeout(1.5)
                s.sendto(probe, (ip, port))
                try:
                    data, src = s.recvfrom(2048)
                    # Reply must come FROM the target and VALIDATE the protocol.
                    if src and src[0] == ip and validator(data):
                        confirmed_open += 1
                        confirmed_ports.append(port)
                    else:
                        open_or_filtered += 1   # reply did not match protocol
                except socket.timeout:
                    open_or_filtered += 1      # silence — open|filtered, UNCONFIRMED
                except OSError:
                    pass                       # ICMP unreachable -> port closed
        except Exception:
            pass
    # Ports with no protocol-specific probe: probed but NOT confirmable. A bare
    # reply here is not proof of service — count as open|filtered only.
    for port in other_ports:
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
                s.settimeout(1.0)
                s.sendto(b"\x00", (ip, port))
                try:
                    s.recvfrom(512)
                    open_or_filtered += 1      # reply but UNVALIDATED -> not graded
                except socket.timeout:
                    open_or_filtered += 1
                except OSError:
                    pass
        except Exception:
            pass
    findings = []
    # Confirmed-open: only an actual UDP reply may carry a graded severity.
    if confirmed_open:
        findings.append(wrap_finding(
            f"UDP service replies confirmed on {confirmed_open}/{len(udp_ports)} ports on {host} ({ip})",
            "LOW" if confirmed_open <= 3 else "MEDIUM",
            cvss="3.0" if confirmed_open <= 3 else "5.0",
            cwe="CWE-200",
            remediation="UDP datagram replies confirm active services; close non-essential UDP at firewall.",
            evidence_marker=f"Replied (confirmed open): {confirmed_ports}"))
    # Timeouts are open|filtered and UNCONFIRMED — INFO only, never vulnerable=True.
    if open_or_filtered:
        findings.append(wrap_finding(
            f"{open_or_filtered} UDP ports open|filtered (unconfirmed — no service reply)",
            "INFO", cvss="0.0", cwe="CWE-200",
            remediation="No UDP reply received — state cannot be confirmed (firewall drop or stateless service). No action required on this signal alone.",
            evidence_marker=f"Probed: {udp_ports}; open|filtered (no reply): {open_or_filtered}"))
    if not findings:
        findings.append(wrap_finding(
            f"No UDP service replies on {host}", "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue least-exposure posture.",
            evidence_marker=f"Probed {len(udp_ports)} common UDP ports — no replies, no open|filtered"))
    sev = "INFO"
    if confirmed_open:
        sev = "LOW" if confirmed_open <= 3 else "MEDIUM"
    return {"tool":"nmap_udp_scan","target":target,"scan_time":0,
            "vulnerable": confirmed_open > 0, "severity": sev,
            "findings": findings,
            "tests_performed": len(udp_ports),
            "tests_summary": f"UDP probe scan of {len(udp_ports)} ports",
            "raw_data": {"ip": ip, "confirmed_open_count": confirmed_open,
                         "confirmed_open_ports": confirmed_ports,
                         "open_or_filtered_count": open_or_filtered}}

def _probe_nmap_version_detect(target, req):
    """Banner grab on top open ports to derive service version."""
    host = _host(target); ip = _resolve(host)
    if not ip:
        return _adv_response("nmap_version_detect", target, "DNS resolution failed",
                              "INFO", "0.0", evidence=host)
    common = [21, 22, 25, 80, 110, 143, 443, 587, 993, 3306, 5432, 6379, 8080]
    services = {}
    for p in common:
        b = _tcp_banner(ip, p, timeout=2.0)
        if b: services[p] = b[:120]

    # Database ports must NOT be named/graded from the port number alone. Only
    # confirm a DB service when the wire protocol actually proves it (zero-FP):
    #   3306 MySQL  -> handshake greeting carries the version + protocol byte
    #   5432 Postgres-> rejects/answers a startup packet (auth-request 'R')
    #   6379 Redis  -> RESP-speaking: replies to PING with +PONG / -ERR / RESP frame
    confirmed_db = _probe_database_services(ip)
    findings = []
    if services:
        findings.append(wrap_finding(
            f"Service banners harvested on {len(services)} ports",
            "INFO", cvss="0.0", cwe="CWE-200",
            remediation="Disable banner disclosure on production services where not required.",
            evidence_marker="; ".join(f"{p}: {b[:60]}" for p,b in services.items())))
    if confirmed_db:
        db_names = ", ".join("{}:{}".format(d["service"], d["port"]) for d in confirmed_db)
        db_evidence = "; ".join("{}/{}: {}".format(d["port"], d["service"], d["evidence"])
                                for d in confirmed_db)
        findings.append(wrap_finding(
            f"Database service(s) protocol-confirmed exposed: {db_names}",
            "MEDIUM", cvss="5.3", cwe="CWE-200",
            remediation="Restrict database ports to application/admin networks; never expose "
                        "MySQL/PostgreSQL/Redis to the public internet.",
            evidence_marker=db_evidence))
    return {"tool":"nmap_version_detect","target":target,"scan_time":0,
            "vulnerable": bool(confirmed_db),
            "severity": "MEDIUM" if confirmed_db else "INFO",
            "findings": findings or [wrap_finding(
                "No service banners harvested", "INFO", cvss="0.0", cwe="N/A",
                remediation="Continue minimal-banner posture.",
                evidence_marker=f"Probed {common}")],
            "tests_performed": len(common),
            "tests_summary": f"Banner grab on {len(common)} common service ports",
            "raw_data": {"ip": ip, "services": services, "confirmed_db": confirmed_db}}

def _probe_nmap_os_detect(target, req):
    """OS fingerprint via TCP/IP stack characteristics (TTL + window)."""
    host = _host(target); ip = _resolve(host)
    if not ip:
        return _adv_response("nmap_os_detect", target, "DNS resolution failed",
                              "INFO", "0.0", evidence=host)
    # Light TTL-based heuristic from an HTTP probe
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(2.0)
            if s.connect_ex((ip, 80)) == 0:
                s.send(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                resp = s.recv(512).decode("utf-8", errors="ignore")
                server_hdr = ""
                for line in resp.split("\r\n"):
                    if line.lower().startswith("server:"):
                        server_hdr = line[7:].strip()
                        break
                os_guess = "Linux/Unix" if "nginx" in server_hdr.lower() or "apache" in server_hdr.lower() else \
                           "Windows" if "iis" in server_hdr.lower() or "microsoft" in server_hdr.lower() else \
                           "Unknown"
                # The Server header is set by the front-most HTTP layer (often a
                # reverse proxy / CDN / load balancer), NOT necessarily the OS of
                # the origin. This is a LOW-CONFIDENCE guess — INFO only, never graded.
                return {"tool":"nmap_os_detect","target":target,"scan_time":0,
                        "vulnerable": False, "severity": "INFO",
                        "findings":[wrap_finding(
                            f"OS guess (low confidence): {os_guess} — heuristic from Server "
                            f"header, which may be a reverse proxy/CDN, not the origin OS",
                            "INFO", cvss="0.0", cwe="CWE-200",
                            remediation="Treat as informational only; the Server header reflects the "
                                        "edge HTTP layer, not necessarily the host OS.",
                            evidence_marker=f"Server: {server_hdr or '(none)'} (reverse-proxy caveat applies)")],
                        "tests_performed": 1,
                        "tests_summary": "OS heuristic from HTTP Server header (low confidence)",
                        "raw_data": {"ip": ip, "server": server_hdr, "os_guess": os_guess,
                                     "confidence": "low"}}
    except Exception:
        pass
    return _adv_response("nmap_os_detect", target, "OS detection inconclusive — no probeable HTTP port",
                          "INFO", "0.0", evidence=f"{host} ({ip})")

def _probe_nmap_default_scripts(target, req):
    """Lightweight 'default scripts' equivalent — banner + headers on web ports."""
    return _probe_nmap_version_detect(target, req) | {"tool":"nmap_default_scripts"}

def _probe_nmap_aggressive(target, req):
    """Aggressive probe — top ports + banners + UDP probe combined."""
    syn = _probe_nmap_syn_scan(target, req)
    ver = _probe_nmap_version_detect(target, req)
    udp = _probe_nmap_udp_scan(target, req)
    findings = (syn.get("findings") or []) + (ver.get("findings") or []) + (udp.get("findings") or [])
    return {"tool":"nmap_aggressive","target":target,"scan_time":0,
            "vulnerable": syn.get("vulnerable") or False, "severity": syn.get("severity","INFO"),
            "findings": findings,
            "tests_performed": (syn.get("tests_performed",0) + ver.get("tests_performed",0) + udp.get("tests_performed",0)),
            "tests_summary": "Aggressive scan: SYN + version + UDP combined",
            "raw_data": {**syn.get("raw_data",{}), "version": ver.get("raw_data",{}), "udp": udp.get("raw_data",{})}}

def _probe_masscan_full_range(target, req):
    """Real masscan binary if installed - falls back to Python socket scan.
    Masscan is 100x faster than Python socket scanning for wide ranges."""
    host = _host(target); ip = _resolve(host)
    if not ip:
        return _adv_response("masscan_full_range", target, "DNS resolution failed",
                              "INFO", "0.0", evidence=host)

    # Try real masscan first
    masscan_path = shutil.which("masscan")
    opens = []
    using_real = False
    if masscan_path:
        # SaaS-safe rate: 1000 pkt/s scan top 1024 ports.
        # --wait=0 doesn't wait for late responses; finishes quickly.
        ec, out, err = _run_bin([
            masscan_path, ip,
            "-p", "1-1024,3306,3389,5432,5601,5900,6379,8080,8443,8888,9090,9200,9300,10250,15672,27017",
            "--rate=1000",
            "--wait=2",
            "-oG", "-",  # grepable to stdout
        ], timeout_s=120)
        if ec in (0, 1) and out:
            using_real = True
            # masscan -oG format: "Host: 1.2.3.4 ()\tPorts: 80/open/tcp//http//"
            for line in out.splitlines():
                m = re.findall(r"(\d+)/open/tcp", line)
                opens.extend(int(p) for p in m)
            opens = sorted(set(opens))

    if not using_real:
        # Fallback to Python socket scan (existing behaviour)
        top200 = list(set(TOP_TCP_PORTS + [
            37,49,79,81,82,88,113,119,179,427,548,554,593,646,873,990,
            1025,1026,1027,1028,1029,1110,1234,1311,1352,1434,1521,1755,
            1900,2000,2001,2049,2121,2717,3128,3268,3306,3690,3703,3986,
            4001,4045,4899,5050,5051,5060,5101,5190,5500,5631,5666,
            5800,5801,5802,5803,5810,5811,5815,5822,5825,5850,5859,5862,
            5877,5900,5901,5902,5903,5904,5906,5907,5910,5915,5922,5925,
            5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,5998,5999,
            6000,6001,6002,6003,6004,6005,6006,6007,6009,6025,6059,6100,
            6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,
            6565,6566,6580,6646,6666,6667,6668,6669,6689,6692,6699,6779,
            6788,6789,6792,6839,6881,6901,6969]))[:200]
        results = _scan_ports(ip, top200, timeout=0.6)
        opens = sorted([p for p, o in results.items() if o])

    engine = "real masscan binary" if using_real else "Python socket fallback"
    cdn = _detect_cdn(host, ip) if opens else ""
    if opens and cdn:
        # CDN/cloud-edge fronted: a wide "open" footprint is the SHARED edge's,
        # not the customer origin. Never graded — INFO with a CDN note (zero-FP).
        finding = wrap_finding(
            f"{len(opens)} open ports on {host} are CDN edge ports, not origin (engine: {engine})",
            "INFO", cvss="0.0", cwe="CWE-200",
            remediation=f"Host fronted by {cdn}; these ports terminate at the shared CDN edge, "
                        "not your origin. Audit the origin host directly.",
            evidence_marker=(f"CDN edge: {cdn}; edge ports: {', '.join(str(p) for p in opens[:40])}"
                              f"{' ... +' + str(len(opens)-40) + ' more' if len(opens)>40 else ''}"))
        sev = "INFO"
    elif opens:
        # Not CDN-fronted: a raw open-port COUNT is NOT proof of a vulnerability.
        # Listing open ports is INFO; a wide footprint warrants review (cap LOW).
        sev = "INFO" if len(opens) <= 10 else "LOW"
        cvss = "0.0" if sev == "INFO" else "3.1"
        finding = wrap_finding(
            f"{len(opens)} TCP ports open on {host} (engine: {engine})",
            sev, cvss=cvss, cwe="CWE-200",
            remediation="Open ports alone are not a vulnerability. Confirm each exposed service "
                        "is intended and access-controlled; apply firewall allow-lists at the edge.",
            evidence_marker=(f"Open ports: {', '.join(str(p) for p in opens[:40])}"
                              f"{' ... +' + str(len(opens)-40) + ' more' if len(opens)>40 else ''}"))
    else:
        sev = "POSITIVE"
        finding = wrap_finding(
            f"Wide port scan: no open ports detected on {host}",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue minimal-exposure posture.",
            evidence_marker=f"Engine: {engine}; 0 of probed ports responded")
    return {"tool": "masscan_full_range", "target": target, "scan_time": 0,
            "vulnerable": False,
            "severity": sev,
            "findings": [finding],
            "tests_performed": len(opens) or 1024,
            "tests_summary": f"masscan ({engine}): {len(opens)} open",
            "raw_data": {"ip": ip, "open_ports": opens, "engine": engine, "cdn": cdn or None}}

def _probe_rustscan_top_ports(target, req):
    return _probe_nmap_syn_scan(target, req) | {"tool":"rustscan_top_ports"}

def _probe_naabu_fast_scan(target, req):
    """Real naabu (projectdiscovery) for fast top-port discovery.
    Falls back to nmap-syn-scan probe if naabu binary missing."""
    host = _host(target); ip = _resolve(host)
    if not ip:
        return _adv_response("naabu_fast_scan", target, "DNS resolution failed",
                              "INFO", "0.0", evidence=host)
    naabu_path = shutil.which("naabu")
    if not naabu_path:
        return _probe_nmap_syn_scan(target, req) | {"tool": "naabu_fast_scan"}

    # naabu -host -top-ports 1000 -silent -json
    ec, out, err = _run_bin([
        naabu_path,
        "-host", ip,
        "-top-ports", "1000",
        "-silent",
        "-json",
        "-rate", "1000",
        "-c", "25",
    ], timeout_s=120)

    opens = []
    if ec in (0, 1) and out:
        for line in out.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                evt = json.loads(line)
                p = evt.get("port")
                if isinstance(p, int):
                    opens.append(p)
            except Exception:
                continue
    opens = sorted(set(opens))

    cdn = _detect_cdn(host, ip) if opens else ""
    if not opens:
        finding = wrap_finding(
            f"naabu fast scan: no open top-1000 ports on {host}",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue minimal-exposure posture.",
            evidence_marker=f"naabu -top-ports 1000 against {ip}: 0 open")
        sev = "POSITIVE"
    elif cdn:
        # CDN-fronted: open ports belong to the shared edge, not the origin.
        sev = "INFO"
        finding = wrap_finding(
            f"naabu: {len(opens)} open ports on {host} are CDN edge ports, not origin",
            "INFO", cvss="0.0", cwe="CWE-200",
            remediation=f"Host fronted by {cdn}; these ports terminate at the shared CDN edge. "
                        "Audit the origin host directly.",
            evidence_marker=f"CDN edge: {cdn}; edge ports: {', '.join(str(p) for p in opens[:40])}")
    else:
        # Raw open-port COUNT is not proof of vulnerability — INFO, cap LOW for a wide footprint.
        sev = "INFO" if len(opens) <= 10 else "LOW"
        cvss = "0.0" if sev == "INFO" else "3.1"
        finding = wrap_finding(
            f"naabu: {len(opens)} open ports of top 1000 on {host}",
            sev, cvss=cvss, cwe="CWE-200",
            remediation="Open ports alone are not a vulnerability. Confirm each exposed service "
                        "is intended and access-controlled.",
            evidence_marker=f"Open: {', '.join(str(p) for p in opens[:40])}")
    return {"tool": "naabu_fast_scan", "target": target, "scan_time": 0,
            "vulnerable": False,
            "severity": sev,
            "findings": [finding],
            "tests_performed": 1000,
            "tests_summary": f"naabu real binary: {len(opens)} open",
            "raw_data": {"ip": ip, "open_ports": opens, "engine": "naabu", "cdn": cdn or None}}

def _probe_unicornscan(target, req):
    return _probe_nmap_udp_scan(target, req) | {"tool":"unicornscan_advisory"}

def _probe_zmap(target, req):
    """ZMap is internet-wide; for SaaS we sample 5 random TCP ports."""
    return _probe_nmap_syn_scan(target, req) | {"tool":"zmap_internet_wide"}

def _probe_hping3(target, req):
    """Real hping3 binary for custom packet crafting + TCP SYN reachability.
    Falls back to Python socket check if hping3 missing or runs as non-root."""
    host = _host(target); ip = _resolve(host)
    if not ip:
        return _adv_response("hping3_custom_packet", target, "DNS resolution failed",
                              "INFO", "0.0", evidence=host)

    hping_path = shutil.which("hping3")
    if hping_path:
        # hping3 needs root for SYN crafting. -c 3 = 3 packets; -S = SYN flag;
        # -p 80 = target port 80. Capture output for parsing.
        ec, out, err = _run_bin([
            hping_path, "-S", "-c", "3", "-p", "80", "--fast", ip,
        ], timeout_s=15)
        # hping3 outputs "len=46 ip=... ttl=... ... flags=SA seq=..." on success
        sa_count = len(re.findall(r"flags=SA", out + err))
        if sa_count > 0:
            return {"tool": "hping3_custom_packet", "target": target, "scan_time": 0,
                    "vulnerable": False, "severity": "POSITIVE",
                    "findings": [wrap_finding(
                        f"hping3: {host} responds to SYN on :80 ({sa_count} SYN+ACK)",
                        "POSITIVE", cvss="0.0", cwe="N/A",
                        remediation="Reachability is expected for public services.",
                        evidence_marker=f"hping3 -S -c 3 -p 80 {ip}: {sa_count} SA responses")],
                    "tests_performed": 3,
                    "tests_summary": "hping3 SYN reachability",
                    "raw_data": {"ip": ip, "engine": "hping3", "sa_count": sa_count}}
        # No SYN+ACK observed - fall through to socket fallback to differentiate
        # "hping3 ran but got no response" from "hping3 missing".

    # Fallback Python socket
    reachable = _tcp_open(ip, 80, timeout=2.0) or _tcp_open(ip, 443, timeout=2.0)
    return {"tool":"hping3_custom_packet","target":target,"scan_time":0,
            "vulnerable": False, "severity": "INFO",
            "findings":[wrap_finding(
                f"Host {'reachable' if reachable else 'unreachable'} via TCP/80 or TCP/443",
                "INFO", cvss="0.0", cwe="CWE-200",
                remediation="Confirm intended network reachability.",
                evidence_marker=f"{host} ({ip}) — TCP probe")],
            "tests_performed": 2,
            "tests_summary": "TCP reachability check (hping3 equivalent)",
            "raw_data": {"ip": ip, "reachable": reachable}}

def _probe_tcptraceroute(target, req):
    return _probe_hping3(target, req) | {"tool":"tcptraceroute_advisory"}

def _probe_netcat_banner_grab(target, req):
    return _probe_nmap_version_detect(target, req) | {"tool":"netcat_banner_grab"}


# ─── LIVE PROBES for tier6 DNS Attacks (partial) ───

def _probe_dns_zone_transfer(target, req):
    """AXFR attempt against the domain's NS."""
    host = _host(target)
    try:
        import dns.query, dns.zone, dns.resolver
        try:
            ns_records = [str(n.target).rstrip(".") for n in dns.resolver.resolve(host, "NS")]
        except Exception:
            ns_records = []
        results = {}
        for ns in ns_records[:3]:
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns, host, timeout=5))
                results[ns] = len(list(z.nodes.keys()))
            except Exception as e:
                results[ns] = f"refused: {str(e)[:50]}"
        leaked = [ns for ns, n in results.items() if isinstance(n, int)]
        if leaked:
            return {"tool":"dns_zone_transfer_axfr","target":target,"scan_time":0,
                    "vulnerable": True, "severity": "HIGH",
                    "findings":[wrap_finding(
                        f"DNS AXFR allowed on {len(leaked)} nameserver(s)",
                        "HIGH", cvss="7.5", cwe="CWE-200",
                        remediation="Restrict AXFR to authorized secondary nameservers only.",
                        evidence_marker=f"Leaked NS: {', '.join(leaked)}")],
                    "tests_performed": len(ns_records),
                    "tests_summary": "DNS zone transfer (AXFR) attempt",
                    "raw_data": {"results": results}}
        return {"tool":"dns_zone_transfer_axfr","target":target,"scan_time":0,
                "vulnerable": False, "severity": "POSITIVE",
                "findings":[wrap_finding(
                    "DNS AXFR correctly refused on all nameservers",
                    "POSITIVE", cvss="0.0", cwe="N/A",
                    remediation="Continue restricting AXFR.",
                    evidence_marker=f"Tested {len(ns_records)} NS, all refused")],
                "tests_performed": len(ns_records),
                "tests_summary": "DNS zone transfer attempt — all refused",
                "raw_data": {"results": results}}
    except ImportError:
        return _adv_response("dns_zone_transfer_axfr", target,
            "dnspython not installed — AXFR probe skipped (advisory mode).",
            "INFO", "0.0", evidence="Install dnspython to enable live AXFR probe.")
    except Exception as e:
        return _adv_response("dns_zone_transfer_axfr", target,
            f"AXFR probe error: {str(e)[:80]}", "INFO", "0.0", evidence=str(e)[:120])

def _probe_dns_open_resolver(target, req):
    """Check if target IP responds as an open recursive DNS resolver."""
    host = _host(target); ip = _resolve(host)
    if not ip:
        return _adv_response("dns_open_resolver_check", target, "DNS resolution failed",
                              "INFO", "0.0", evidence=host)
    try:
        # Build a simple A query for google.com with a known XID (0x1234).
        _XID = (0x12, 0x34)
        query = bytes([_XID[0], _XID[1], 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        6])+b"google"+bytes([3])+b"com"+bytes([0, 0, 1, 0, 1])
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
            s.settimeout(3.0)
            s.sendto(query, (ip, 53))
            try:
                data, src = s.recvfrom(512)
                # Zero-FP gating before flagging an open resolver:
                #   (1) reply must come FROM the target host (not a spoof/relay),
                #   (2) DNS XID must echo our request (bytes 0-1),
                #   (3) QR bit set (this IS a response, byte 2 high bit),
                #   (4) ANCOUNT (bytes 6-7) > 0 (it actually RESOLVED the external name).
                src_ok = bool(src) and src[0] == ip
                xid_ok = len(data) >= 2 and data[0] == _XID[0] and data[1] == _XID[1]
                qr_ok = len(data) >= 3 and (data[2] & 0x80) == 0x80
                ancount_ok = len(data) >= 8 and (data[6] | data[7]) > 0
                if src_ok and xid_ok and qr_ok and ancount_ok:
                    return {"tool":"dns_open_resolver_check","target":target,"scan_time":0,
                            "vulnerable": True, "severity": "HIGH",
                            "findings":[wrap_finding(
                                "Open DNS resolver — recursive query for external domain succeeded",
                                "HIGH", cvss="7.0", cwe="CWE-918",
                                remediation="Disable recursion for external clients; use views/ACLs.",
                                evidence_marker=f"{ip}:53 answered recursive query (XID echoed, QR set, ANCOUNT > 0)")],
                            "tests_performed": 1,
                            "tests_summary": "Open recursive DNS resolver check",
                            "raw_data": {"ip": ip, "anscount_bytes": list(data[6:8]),
                                         "src_match": src_ok, "xid_match": xid_ok}}
                # A reply that fails XID/source/QR/ANCOUNT validation is NOT proof
                # of an open resolver (firewall echo / NXDOMAIN / spoof) — treated
                # as "refused/non-recursive" (POSITIVE), never graded.
                return {"tool":"dns_open_resolver_check","target":target,"scan_time":0,
                        "vulnerable": False, "severity": "POSITIVE",
                        "findings":[wrap_finding(
                            "DNS server refused recursive query for external domain (good)",
                            "POSITIVE", cvss="0.0", cwe="N/A",
                            remediation="Continue restricting recursion.",
                            evidence_marker=f"{ip}:53 returned ANCOUNT=0 for google.com")],
                        "tests_performed": 1, "tests_summary": "Open recursive DNS resolver check",
                        "raw_data": {"ip": ip}}
            except socket.timeout:
                return _adv_response("dns_open_resolver_check", target,
                    "No DNS response — port 53 may be filtered or service not running",
                    "POSITIVE", "0.0", evidence=f"{ip}:53 silent")
    except Exception as e:
        return _adv_response("dns_open_resolver_check", target,
            f"Resolver probe error: {str(e)[:80]}", "INFO", "0.0", evidence=str(e)[:120])


# ─── HTTP helper + NEW live DNS probes ───
def _http_get(url, timeout=4):
    try:
        r = urllib.request.Request(url, headers={"User-Agent": "VulnusLab/2.0"})
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read(4096).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(4096).decode("utf-8", errors="ignore")
        except Exception:
            return e.code, ""
    except Exception:
        return 0, ""


def _resp(tool, target, findings, tested, summary):
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "POSITIVE": 0}
    top = "INFO"
    for f in findings:
        if sev_order.get(f.get("severity", "INFO"), 0) > sev_order.get(top, 0):
            top = f.get("severity", "INFO")
    return {"tool": tool, "target": target, "scan_time": 0,
            "vulnerable": top in ("CRITICAL", "HIGH", "MEDIUM"),
            "severity": top, "findings": findings,
            "tests_performed": tested, "tests_summary": summary, "raw_data": {}}


def _abd(slug, title, reason, cwe="CWE-1395"):
    """Factory: advisory-by-design probe (cannot be SaaS-probed over the internet)."""
    def _p(target, req):
        return _advisory_by_design_response(slug, target, title, reason=reason, cwe=cwe)
    return _p


# Inline fallback signatures. Kept verbatim so the takeover probe still works
# if the VL-CORE pool (tools/_payloads/network/subdomain_takeover_sigs.json) is
# missing during a partial deploy / dev env. The AI-curated pool, when present,
# supersedes this list (see _load_takeover_sigs below). Shape: (cname-suffix,
# unclaimed-resource-fingerprint) — fingerprint must be a SPECIFIC, lowercased
# substring the provider returns ONLY for an unregistered resource. The probe
# requires BOTH a CNAME-suffix match AND a fingerprint body-match (zero-FP).
_TAKEOVER_SIGS_FALLBACK = [
    ("github.io", "there isn't a github pages site here"),
    ("herokuapp.com", "no such app"),
    ("s3.amazonaws.com", "nosuchbucket"),
    ("azurewebsites.net", "404 web site not found"),
    ("trafficmanager.net", "404 web site not found"),
    ("fastly.net", "fastly error: unknown domain"),
    ("pantheonsite.io", "404 error unknown site"),
    ("wordpress.com", "do you want to register"),
    ("ghost.io", "domain error"),
    ("surge.sh", "project not found"),
    ("bitbucket.io", "repository not found"),
    ("readthedocs.io", "unknown to read the docs"),
    ("statuspage.io", "you are being redirected"),
    ("netlify.app", "not found - request id"),
    ("myshopify.com", "sorry, this shop is currently unavailable"),
    ("zendesk.com", "help center closed"),
]


def _load_takeover_sigs():
    """Load the AI-curated subdomain-takeover pool and flatten it to the
    [(cname-suffix, fingerprint), ...] shape the probe expects.

    Each JSON entry carries one or more 'suffixes' and ONE 'fingerprint', so a
    service with N suffixes expands to N tuples. Suffix + fingerprint are
    lowercased to match the probe (which lowercases both the CNAME and the body).
    On any failure / empty pool we fall back to the inline list so the check
    never silently goes dark. The matching contract (CNAME-confirm + specific
    fingerprint) is unchanged.
    """
    try:
        from tools._payloads.network import _loader as _net_loader
        data = _net_loader.load_json("subdomain_takeover_sigs", fallback=None)
    except Exception:
        data = None
    if not isinstance(data, dict):
        return list(_TAKEOVER_SIGS_FALLBACK)
    sigs = data.get("signatures") or []
    out = []
    for entry in sigs:
        if not isinstance(entry, dict):
            continue
        fp = (entry.get("fingerprint") or "").strip().lower()
        if not fp:
            continue
        for suf in entry.get("suffixes") or []:
            suf = (suf or "").strip().lower()
            if suf:
                out.append((suf, fp))
    return out or list(_TAKEOVER_SIGS_FALLBACK)


# Active signature list: curated pool when available, inline fallback otherwise.
_TAKEOVER_SIGS = _load_takeover_sigs()


def _probe_subdomain_takeover(target, req):
    """Detect a dangling CNAME pointing to an unclaimed third-party service."""
    host = _host(target)
    try:
        import dns.resolver
        try:
            cnames = [str(r.target).rstrip(".").lower() for r in dns.resolver.resolve(host, "CNAME")]
        except Exception:
            cnames = []
    except ImportError:
        return _adv_response("dns_subdomain_takeover_check", target,
            "dnspython not installed — CNAME takeover probe skipped",
            "INFO", "0.0", evidence="Install dnspython to enable the takeover check.")
    sig_map = dict(_TAKEOVER_SIGS)
    # The customer's own apex/registrable domain — a CNAME that resolves back to
    # the customer's OWN infra (e.g. host.example.com -> cdn.example.com) is NOT
    # a third-party takeover candidate. Strip leading "www." for a fair compare.
    own_apex = host[4:] if host.startswith("www.") else host
    findings = []; flagged = []
    for cn in cnames:
        # Exact suffix match: the CNAME must END WITH a known takeover-service
        # domain (e.g. "foo.s3.amazonaws.com" endswith "s3.amazonaws.com"), not
        # merely CONTAIN the substring somewhere (which false-positives on names
        # like "amazonaws.com.attacker.example"). Pick the longest match.
        matches = [s for s, _ in _TAKEOVER_SIGS
                   if cn == s or cn.endswith("." + s)]
        svc = max(matches, key=len) if matches else None
        if not svc:
            continue
        # Skip CNAMEs that point at the customer's OWN domain — that is the
        # customer's infrastructure, not an unclaimed third-party resource.
        if cn == own_apex or cn.endswith("." + own_apex):
            continue
        body_all = ""
        for scheme in ("https", "http"):
            _, body = _http_get(f"{scheme}://{host}/", timeout=4)
            body_all += " " + body.lower()
        # Only grade HIGH when the provider's UNCLAIMED-resource fingerprint is
        # actually present in the body (proves the resource is dangling/claimable).
        if sig_map[svc] in body_all:
            flagged.append(f"{host} -> {cn} ({svc})")
        else:
            # CNAME points at a takeover-prone service but the resource still
            # answers / shows no dangling signature -> almost certainly CLAIMED.
            # Informational only, never graded as a takeover.
            findings.append(wrap_finding(
                f"CNAME to third-party service '{svc}' — resource appears claimed (no dangling signature)",
                "INFO", cvss="0.0", cwe="CWE-350",
                remediation="No takeover indicator found. Track this dependency and remove the "
                            "CNAME if the third-party resource is ever decommissioned.",
                evidence_marker=f"{host} -> {cn} (no unclaimed-resource fingerprint in response)"))
    if flagged:
        findings.insert(0, wrap_finding(
            f"Subdomain takeover POSSIBLE — {len(flagged)} dangling CNAME(s) with unclaimed-resource fingerprint",
            "HIGH", cvss="8.0", cwe="CWE-350",
            remediation="Remove the dangling DNS record or immediately reclaim the third-party resource.",
            evidence_marker="; ".join(flagged[:5])))
    if not findings:
        findings.append(wrap_finding(
            "No dangling CNAME / subdomain-takeover indicator",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="No action for this check.",
            evidence_marker=f"{len(cnames)} CNAME(s) checked" if cnames else "No CNAME records for this host"))
    return _resp("dns_subdomain_takeover_check", target, findings, max(1, len(cnames)),
                 "Subdomain-takeover dangling-CNAME probe")


def _probe_nsec_walk(target, req):
    """DNSSEC NSEC zone-walk — enumerate zone names if NSEC (not NSEC3) is used."""
    host = _host(target)
    try:
        import dns.resolver, dns.message, dns.query, dns.rdatatype
    except ImportError:
        return _adv_response("dns_walk_nsec", target,
            "dnspython not installed — NSEC walk skipped", "INFO", "0.0",
            evidence="Install dnspython to enable the NSEC walk.")
    ns_ip = None
    try:
        ns_list = [str(n.target).rstrip(".") for n in dns.resolver.resolve(host, "NS")]
        if ns_list:
            ns_ip = socket.gethostbyname(ns_list[0])
    except Exception:
        ns_ip = None
    if not ns_ip:
        return _adv_response("dns_walk_nsec", target,
            "No authoritative nameserver resolved — NSEC walk not possible",
            "INFO", "0.0", evidence=host)
    names = []
    cur = host
    try:
        for _ in range(20):
            q = dns.message.make_query(cur, dns.rdatatype.NSEC, want_dnssec=True)
            resp = dns.query.udp(q, ns_ip, timeout=4)
            nxt = None
            for rrset in list(resp.answer) + list(resp.authority):
                if rrset.rdtype == dns.rdatatype.NSEC:
                    nxt = str(rrset[0].next).rstrip(".")
                    break
            if not nxt or nxt in names or not nxt.endswith(host):
                break
            names.append(nxt); cur = nxt
    except Exception:
        pass
    if len(names) > 1:
        # NSEC walkability alone discloses zone contents, but the SENSITIVITY of
        # what it reveals drives the grade. Walking only the apex/www is not a
        # material exposure (INFO); revealing non-public/sensitive names (admin,
        # internal, vpn, staging, db, mail, etc.) is the real risk (MEDIUM).
        _SENSITIVE = ("admin", "internal", "intranet", "vpn", "dev", "test",
                      "staging", "stage", "uat", "qa", "db", "database", "sql",
                      "mail", "smtp", "git", "jenkins", "ci", "backup", "ftp",
                      "ssh", "rdp", "panel", "portal", "api-internal", "corp",
                      "private", "secret", "vault", "grafana", "kibana", "k8s")
        apex = host[4:] if host.startswith("www.") else host
        sensitive_hits = []
        for n in names:
            label = n[:-(len(apex) + 1)] if n.endswith("." + apex) else n
            label_l = label.lower()
            if label_l and label_l not in ("www",) and any(
                    tok in label_l for tok in _SENSITIVE):
                sensitive_hits.append(n)
        if sensitive_hits:
            findings = [wrap_finding(
                f"DNSSEC NSEC zone-walk revealed {len(sensitive_hits)} sensitive name(s) "
                f"of {len(names)} enumerated — non-public hostnames disclosed",
                "MEDIUM", cvss="5.3", cwe="CWE-200",
                remediation="Migrate from NSEC to NSEC3 (adequate iterations / opt-out) to block zone walking.",
                evidence_marker="Sensitive: " + ", ".join(sensitive_hits[:8]) +
                                (" ..." if len(sensitive_hits) > 8 else ""))]
        else:
            findings = [wrap_finding(
                f"DNSSEC NSEC zone-walk enumerated {len(names)} record(s) — only public/expected names",
                "INFO", cvss="0.0", cwe="CWE-200",
                remediation="Walkable NSEC is best-practice-against, but no sensitive names were "
                            "revealed here. Consider NSEC3 to harden against future enumeration.",
                evidence_marker=", ".join(names[:8]) + (" ..." if len(names) > 8 else ""))]
    else:
        findings = [wrap_finding(
            "No NSEC zone-walk possible (NSEC3 in use or DNSSEC not signed)",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="No action for this check.",
            evidence_marker="NSEC chain not walkable")]
    return _resp("dns_walk_nsec", target, findings, max(1, len(names)), "DNSSEC NSEC zone-walk probe")


# Reusable advisory reasons
_LAN = ("Requires Layer-2 adjacency on the target's local network; an external SaaS "
        "scanner over the internet cannot reach this attack surface.")
_ACTIVE = ("This is an active spoofing/poisoning/relay attack that intercepts or disrupts "
           "live traffic — out of Vulnerability-Assessment scope and never run against a "
           "production target.")
_DOS = ("Confirming this needs flooding/amplification load that is unsafe to run against a "
        "production target from a SaaS scanner.")
_SNIFF = ("Requires local packet capture on the target network segment; a remote SaaS "
          "scanner has no on-wire traffic to inspect.")
_IPV6LAN = ("Requires IPv6 Layer-2 adjacency on the target LAN; cannot be performed remotely.")
_FUZZ = ("Active protocol fuzzing can crash the target service; out of VA scope and not run "
         "against production.")
_RECON = ("Covered comprehensively by the Recon module's subdomain enumeration; run that module.")
_MANUAL = "Analyst task — interactive proxy / manual operation."


PROBES = {
    # §1 Port & Service Enumeration (14 live)
    "nmap_syn_scan":          _probe_nmap_syn_scan,
    "nmap_udp_scan":          _probe_nmap_udp_scan,
    "nmap_version_detect":    _probe_nmap_version_detect,
    "nmap_os_detect":         _probe_nmap_os_detect,
    "nmap_default_scripts":   _probe_nmap_default_scripts,
    "nmap_aggressive":        _probe_nmap_aggressive,
    "masscan_full_range":     _probe_masscan_full_range,
    "rustscan_top_ports":     _probe_rustscan_top_ports,
    "naabu_fast_scan":        _probe_naabu_fast_scan,
    "unicornscan_advisory":   _probe_unicornscan,
    "zmap_internet_wide":     _probe_zmap,
    "hping3_custom_packet":   _probe_hping3,
    "tcptraceroute_advisory": _probe_tcptraceroute,
    "netcat_banner_grab":     _probe_netcat_banner_grab,
    # §6 DNS Attacks (4 live)
    "dns_zone_transfer_axfr": _probe_dns_zone_transfer,
    "dns_open_resolver_check": _probe_dns_open_resolver,
    "dns_subdomain_takeover_check": _probe_subdomain_takeover,
    "dns_walk_nsec":          _probe_nsec_walk,

    # §2 LAN Attacks (Layer 2) — require local network adjacency
    "arp_spoofing":           _abd("arp_spoofing", "ARP spoofing", _ACTIVE),
    "mac_flooding_macof":     _abd("mac_flooding_macof", "MAC flooding (CAM-table overflow)", _LAN),
    "vlan_hopping_dtp":       _abd("vlan_hopping_dtp", "VLAN hopping (DTP/double-tag)", _LAN),
    "stp_root_bridge":        _abd("stp_root_bridge", "STP root-bridge takeover", _LAN),
    "dhcp_starvation":        _abd("dhcp_starvation", "DHCP starvation", _LAN),
    "dhcp_rogue_server":      _abd("dhcp_rogue_server", "DHCP rogue server", _ACTIVE),
    "cdp_lldp_enum":          _abd("cdp_lldp_enum", "CDP/LLDP enumeration", _LAN),
    "hsrp_vrrp_takeover":     _abd("hsrp_vrrp_takeover", "HSRP/VRRP/GLBP hijack", _LAN),
    "yersinia_advisory":      _abd("yersinia_advisory", "Yersinia L2 attack suite", _LAN),

    # §3 MITM — active interception, require local position
    "ettercap_mitm":          _abd("ettercap_mitm", "Ettercap MITM", _ACTIVE),
    "bettercap_advisory":     _abd("bettercap_advisory", "bettercap automated MITM", _ACTIVE),
    "mitmproxy_advisory":     _abd("mitmproxy_advisory", "mitmproxy interception", _ACTIVE),
    "burp_intercept":         _abd("burp_intercept", "Burp Suite intercept", _MANUAL),
    "ssl_strip":              _abd("ssl_strip", "SSLStrip / HSTS-bypass MITM", _ACTIVE),
    "dns_spoof_local":        _abd("dns_spoof_local", "DNS spoofing (LAN)", _ACTIVE),
    "icmp_redirect":          _abd("icmp_redirect", "ICMP redirect attack", _ACTIVE),

    # §4 DoS / DDoS — disruptive load, unsafe against production
    "syn_flood_advisory":     _abd("syn_flood_advisory", "TCP SYN flood", _DOS),
    "udp_flood_advisory":     _abd("udp_flood_advisory", "UDP flood", _DOS),
    "icmp_flood_advisory":    _abd("icmp_flood_advisory", "ICMP flood / smurf", _DOS),
    "slowloris_http_advisory": _abd("slowloris_http_advisory", "Slowloris (slow-header DoS)", _DOS),
    "http_get_post_flood":    _abd("http_get_post_flood", "HTTP GET/POST flood", _DOS),
    "amplification_ntp_advisory": _abd("amplification_ntp_advisory", "NTP amplification", _DOS),
    "amplification_dns_advisory": _abd("amplification_dns_advisory", "DNS amplification", _DOS),
    "amplification_memcached_advisory": _abd("amplification_memcached_advisory", "Memcached amplification", _DOS),

    # §5 Sniffing & Capture — require on-segment packet capture
    "tcpdump_advisory":       _abd("tcpdump_advisory", "tcpdump capture", _SNIFF),
    "wireshark_advisory":     _abd("wireshark_advisory", "Wireshark analysis", _SNIFF),
    "dumpcap_advisory":       _abd("dumpcap_advisory", "dumpcap capture", _SNIFF),
    "tshark_advisory":        _abd("tshark_advisory", "tshark capture", _SNIFF),
    "ngrep_advisory":         _abd("ngrep_advisory", "ngrep capture", _SNIFF),
    "p0f_passive_os":         _abd("p0f_passive_os", "p0f passive OS fingerprint", _SNIFF),
    "net_creds_credential_extract": _abd("net_creds_credential_extract", "net-creds plaintext-cred harvest", _SNIFF),
    "pcredz_credential_extract": _abd("pcredz_credential_extract", "PCredz NTLM/cred extraction", _SNIFF),

    # §6 DNS Attacks — remaining (active / DoS / covered-by-Recon)
    "dns_cache_poisoning":    _abd("dns_cache_poisoning", "DNS cache poisoning", _ACTIVE),
    "dns_subdomain_enum_brute": _abd("dns_subdomain_enum_brute", "DNS subdomain brute-force", _RECON),
    "dns_dnscat2_tunnel":     _abd("dns_dnscat2_tunnel", "DNS tunneling detection (dnscat2)", _SNIFF),
    "dns_hijack_advisory":    _abd("dns_hijack_advisory", "DNS hijack", _ACTIVE),
    "dns_random_subdomain_attack": _abd("dns_random_subdomain_attack", "Random-subdomain (water-torture) attack", _DOS),

    # §7 IPv6 Attacks — require IPv6 LAN adjacency
    "ipv6_router_advertisement_spoof": _abd("ipv6_router_advertisement_spoof", "IPv6 RA spoof (mitm6)", _IPV6LAN),
    "ipv6_dhcpv6_spoof":      _abd("ipv6_dhcpv6_spoof", "DHCPv6 rogue server", _IPV6LAN),
    "ipv6_smurf_advisory":    _abd("ipv6_smurf_advisory", "IPv6 Smurf", _DOS),
    "ipv6_neighbor_discovery_spoof": _abd("ipv6_neighbor_discovery_spoof", "NDP spoof", _IPV6LAN),
    "ipv6_packet_fragmentation_evasion": _abd("ipv6_packet_fragmentation_evasion", "IPv6 fragmentation evasion", _IPV6LAN),
    "ipv6_slaac_attack":      _abd("ipv6_slaac_attack", "SLAAC attack", _IPV6LAN),
    "ipv6_address_enum_thc_alive6": _abd("ipv6_address_enum_thc_alive6", "IPv6 address enum (THC alive6)", _IPV6LAN),

    # §8 Protocol Fuzzing — active, can crash the service
    "fuzzing_smb_advisory":   _abd("fuzzing_smb_advisory", "SMB protocol fuzzing", _FUZZ),
    "fuzzing_rdp_advisory":   _abd("fuzzing_rdp_advisory", "RDP protocol fuzzing", _FUZZ),
    "fuzzing_dns_advisory":   _abd("fuzzing_dns_advisory", "DNS protocol fuzzing", _FUZZ),
    "fuzzing_http2_advisory": _abd("fuzzing_http2_advisory", "HTTP/2 protocol fuzzing", _FUZZ),
    "fuzzing_quic_advisory":  _abd("fuzzing_quic_advisory", "QUIC protocol fuzzing", _FUZZ),
}

TECHNIQUES = [
    # §1 Port & Service Enumeration (14)
    ("nmap_syn_scan", "nmap SYN scan.", "INFO", "0.0"),
    ("nmap_udp_scan", "nmap UDP scan.", "INFO", "0.0"),
    ("nmap_version_detect", "nmap version detect (-sV).", "INFO", "0.0"),
    ("nmap_os_detect", "nmap OS detect (-O).", "INFO", "0.0"),
    ("nmap_default_scripts", "nmap default scripts (-sC).", "INFO", "0.0"),
    ("nmap_aggressive", "nmap aggressive (-A).", "INFO", "0.0"),
    ("masscan_full_range", "masscan full port range.", "INFO", "0.0"),
    ("rustscan_top_ports", "RustScan top ports.", "INFO", "0.0"),
    ("naabu_fast_scan", "naabu fast port scan.", "INFO", "0.0"),
    ("unicornscan_advisory", "unicornscan async scan.", "INFO", "0.0"),
    ("zmap_internet_wide", "ZMap internet-wide scan.", "INFO", "0.0"),
    ("hping3_custom_packet", "hping3 custom packet crafting.", "MEDIUM", "5.0"),
    ("tcptraceroute_advisory", "tcptraceroute.", "INFO", "0.0"),
    ("netcat_banner_grab", "netcat banner grab.", "INFO", "0.0"),
    # §2 LAN Attacks (9)
    ("arp_spoofing", "ARP spoofing (arpspoof).", "HIGH", "7.5"),
    ("mac_flooding_macof", "MAC flooding (macof).", "HIGH", "7.0"),
    ("vlan_hopping_dtp", "VLAN hopping (DTP).", "HIGH", "7.0"),
    ("stp_root_bridge", "STP root-bridge attack.", "HIGH", "7.5"),
    ("dhcp_starvation", "DHCP starvation.", "HIGH", "7.0"),
    ("dhcp_rogue_server", "DHCP rogue server.", "HIGH", "7.5"),
    ("cdp_lldp_enum", "CDP/LLDP enumeration.", "MEDIUM", "5.0"),
    ("hsrp_vrrp_takeover", "HSRP/VRRP takeover.", "HIGH", "8.0"),
    ("yersinia_advisory", "Yersinia L2 attacks.", "HIGH", "7.5"),
    # §3 MITM (7)
    ("ettercap_mitm", "Ettercap MITM.", "HIGH", "7.5"),
    ("bettercap_advisory", "bettercap.", "HIGH", "7.5"),
    ("mitmproxy_advisory", "mitmproxy.", "HIGH", "7.5"),
    ("burp_intercept", "Burp Suite intercept.", "HIGH", "7.0"),
    ("ssl_strip", "SSLStrip.", "HIGH", "7.5"),
    ("dns_spoof_local", "DNS spoof (local).", "HIGH", "7.5"),
    ("icmp_redirect", "ICMP redirect attack.", "MEDIUM", "5.5"),
    # §4 DoS / DDoS (8)
    ("syn_flood_advisory", "SYN flood advisory.", "HIGH", "7.0"),
    ("udp_flood_advisory", "UDP flood advisory.", "HIGH", "7.0"),
    ("icmp_flood_advisory", "ICMP flood advisory.", "MEDIUM", "5.0"),
    ("slowloris_http_advisory", "Slowloris HTTP advisory.", "HIGH", "7.5"),
    ("http_get_post_flood", "HTTP GET/POST flood.", "HIGH", "7.0"),
    ("amplification_ntp_advisory", "NTP amplification advisory.", "HIGH", "7.5"),
    ("amplification_dns_advisory", "DNS amplification advisory.", "HIGH", "7.5"),
    ("amplification_memcached_advisory", "Memcached amplification advisory.", "HIGH", "7.5"),
    # §5 Sniffing & Capture (8)
    ("tcpdump_advisory", "tcpdump capture.", "INFO", "0.0"),
    ("wireshark_advisory", "Wireshark capture.", "INFO", "0.0"),
    ("dumpcap_advisory", "dumpcap capture.", "INFO", "0.0"),
    ("tshark_advisory", "tshark capture.", "INFO", "0.0"),
    ("ngrep_advisory", "ngrep capture.", "INFO", "0.0"),
    ("p0f_passive_os", "p0f passive OS fingerprint.", "INFO", "0.0"),
    ("net_creds_credential_extract", "net-creds credential extract from pcap.", "HIGH", "7.5"),
    ("pcredz_credential_extract", "PCredz cred extraction.", "HIGH", "7.5"),
    # §6 DNS Attacks (9)
    ("dns_cache_poisoning", "DNS cache poisoning.", "HIGH", "8.0"),
    ("dns_zone_transfer_axfr", "DNS zone transfer (AXFR).", "MEDIUM", "5.5"),
    ("dns_subdomain_enum_brute", "DNS subdomain enum brute.", "INFO", "0.0"),
    ("dns_walk_nsec", "DNSSEC NSEC walking.", "MEDIUM", "5.0"),
    ("dns_dnscat2_tunnel", "DNS tunneling (dnscat2).", "HIGH", "7.5"),
    ("dns_subdomain_takeover_check", "Subdomain takeover check.", "HIGH", "8.0"),
    ("dns_hijack_advisory", "DNS hijack advisory.", "HIGH", "7.5"),
    ("dns_open_resolver_check", "Open resolver check.", "HIGH", "7.0"),
    ("dns_random_subdomain_attack", "Random subdomain attack.", "HIGH", "7.0"),
    # §7 IPv6 Attacks (7)
    ("ipv6_router_advertisement_spoof", "IPv6 RA spoof (mitm6).", "HIGH", "8.0"),
    ("ipv6_dhcpv6_spoof", "DHCPv6 spoof.", "HIGH", "8.0"),
    ("ipv6_smurf_advisory", "IPv6 Smurf advisory.", "MEDIUM", "5.0"),
    ("ipv6_neighbor_discovery_spoof", "ND spoof.", "HIGH", "7.5"),
    ("ipv6_packet_fragmentation_evasion", "IPv6 fragmentation evasion.", "MEDIUM", "5.5"),
    ("ipv6_slaac_attack", "SLAAC attack.", "HIGH", "7.5"),
    ("ipv6_address_enum_thc_alive6", "IPv6 address enum (THC alive6).", "INFO", "0.0"),
    # §8 Protocol Fuzzing (5)
    ("fuzzing_smb_advisory", "SMB protocol fuzzing.", "MEDIUM", "5.0"),
    ("fuzzing_rdp_advisory", "RDP protocol fuzzing.", "MEDIUM", "5.0"),
    ("fuzzing_dns_advisory", "DNS protocol fuzzing.", "MEDIUM", "5.0"),
    ("fuzzing_http2_advisory", "HTTP/2 protocol fuzzing.", "MEDIUM", "5.0"),
    ("fuzzing_quic_advisory", "QUIC protocol fuzzing .", "MEDIUM", "5.0"),
]

router = make_advisory_router("network", TECHNIQUES,
    playbook_ref="See module_playbooks/16_network.md.",
    probes=PROBES)


def register(app):
    app.include_router(router)
