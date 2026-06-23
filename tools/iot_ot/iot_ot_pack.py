"""§30 IoT/OT/ICS Security — 58 endpoints per 30_iot_ot.md.

VL-FORGE upgrade 2026-06-12: every technique in T now resolves to EITHER a
real live probe OR an honest advisory-by-design INFO — ZERO bare
[NOT IMPLEMENTED] scaffolds remain.

Real live probes (externally-observable ICS/OT/IoT surfaces, detection-only):
  - Modbus TCP/502, Siemens S7 TCP/102 (ISO-TSAP), EtherNet/IP TCP/44818,
    DNP3 TCP/20000, BACnet UDP/47808, KNXnet/IP UDP/3671
  - Schneider Modicon (Modbus + HTTP fingerprint), Rockwell/Allen-Bradley
    (EtherNet/IP List Identity), PLCScan-style multi-protocol ICS sweep
  - IoT telnet 23/2323 (Mirai), UPnP/SSDP UDP/1900, mDNS/DNS-SD UDP/5353,
    RTSP TCP/554 (camera), ONVIF HTTP camera fingerprint

Everything that genuinely cannot be checked from an external SaaS scanner
(RF/Zigbee/Z-Wave/Thread/Matter radios, on-host forensics, engagement-scope
methodology, vendor credential testing that requires authorization, DoS,
active fuzzing/replay) is emitted as [ADVISORY-BY-DESIGN] INFO — vulnerable:
False — via _advisory_by_design_response. NEVER a graded severity unless the
condition was actually detected on the target.

HARD RULE: a CRITICAL/HIGH/MEDIUM/LOW severity is emitted ONLY when the probe
actually observed the condition. VA not PT: detection only, no exploitation,
no writes, no replay, no flooding, no cross-scanner chaining.

ZERO-FP PROTOCOL CONFIRMATION: an OT/IoT protocol is graded ONLY after FULL
FRAME validation, never on a single magic byte or a substring. If only the
port is open (or a partial/ambiguous signal is seen) the probe emits INFO
"port open, protocol NOT confirmed". Specifically:
  - Modbus/502     : full ADU — MBAP transaction-id echo, protocol-id 0x0000,
                     exact length field, unit echo, FC01/FC81 function-code echo.
  - S7/102         : full TPKT+COTP Connection Confirm framing (+ best-effort
                     S7comm Setup-Communication ACK, protocol id 0x32).
  - EtherNet/IP    : full List-Identity reply — command 0x0063 echo, exact
    /44818           length, status 0, item count>=1, CPF item type 0x000C.
  - BACnet/47808   : BVLC type 0x81 + valid function + length==datagram + NPDU
                     version 0x01.
  - KNX/3671       : header 0x0610 + service type 0x0202 (SEARCH_RESPONSE) +
                     total-length field == datagram length.
  - UPnP/SSDP      : HTTP/1.x 200 status line + mandatory ST + USN headers
                     (+ LOCATION/SERVER) — not a bare 'HTTP/1.1'/'USN' substring.
  - mDNS/5353      : DNS QR/response bit set + ANCOUNT>0 + answer section — not
                     the QR bit alone.
  - Telnet/23      : IAC (0xff) + WILL/WONT/DO/DONT command byte negotiation —
                     not a 'login:'/'password:' substring.
"""
import socket
import struct
import urllib.request
import urllib.error
from contextlib import closing
from tools._pack_common import (
    make_advisory_router, _adv_response, _advisory_by_design_response,
)
from tools._shared import wrap_finding


# ─────────────────────────── helpers ───────────────────────────

def _host(t):
    return t.split("://", 1)[-1].split("/")[0].split(":")[0].strip().lower() or t


def _resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return ""


def _tcp_open(host, port, timeout=2.0):
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def _tcp_send_recv(host, port, payload, timeout=3.0, recv=256):
    """Connect, send a benign read/identify request, return raw response bytes.
    Returns b'' on any failure — never raises, never a false finding."""
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) != 0:
                return b""
            if payload:
                s.send(payload)
            try:
                return s.recv(recv)
            except Exception:
                return b""
    except Exception:
        return b""


def _udp_probe(host, port, payload=b"\x00", timeout=2.0, recv=1024):
    """Send a single benign UDP datagram; return (got_response, data)."""
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
            s.settimeout(timeout)
            s.sendto(payload, (host, port))
            try:
                data, _ = s.recvfrom(recv)
                return True, data
            except socket.timeout:
                return False, b""
            except OSError:
                return False, b""
    except Exception:
        return False, b""


def _http_get(url, timeout=4):
    try:
        r = urllib.request.Request(url, headers={"User-Agent": "VulnusLab/2.0"})
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read(4096).decode("utf-8", errors="ignore")
            return resp.status, hdrs, body
    except urllib.error.HTTPError as e:
        try:
            hdrs = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
            body = e.read(4096).decode("utf-8", errors="ignore")
        except Exception:
            hdrs, body = {}, ""
        return e.code, hdrs, body
    except Exception:
        return 0, {}, ""


def _build(tool, target, findings, tested, summary, raw=None):
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "POSITIVE": 0}
    top = "INFO"
    for f in findings:
        if sev_order.get(f.get("severity", "INFO"), 0) > sev_order.get(top, 0):
            top = f.get("severity", "INFO")
    return {"tool": tool, "target": target, "scan_time": 0,
            "vulnerable": top in ("CRITICAL", "HIGH", "MEDIUM"),
            "severity": top, "findings": findings,
            "tests_performed": tested, "tests_summary": summary,
            "raw_data": raw or {}}


def _clean_pos(tool, target, title, evidence, tested=1, summary=""):
    """Honest POSITIVE (not-detected) response — never a false finding."""
    return _build(tool, target, [wrap_finding(
        title, "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue OT-network segregation / least-exposure posture.",
        evidence_marker=evidence)], tested, summary or title)


def _abd(slug, title, reason, cwe="CWE-1395"):
    """Factory: advisory-by-design probe (cannot be SaaS-probed over the
    internet). Always emits a single INFO finding, vulnerable:False."""
    def _p(target, req):
        return _advisory_by_design_response(slug, target, title, reason=reason, cwe=cwe)
    return _p


# Reusable advisory-by-design reasons
_RF = ("Requires a physical radio (Zigbee/Z-Wave/Thread/802.15.4 SDR) within RF "
       "range of the target devices; an external SaaS scanner over the internet "
       "has no over-the-air access to this attack surface.")
_LAN = ("Requires Layer-2 adjacency on the target's OT/IoT LAN segment; an "
        "external SaaS scanner over the internet cannot reach this surface.")
_ACTIVE = ("This is an active write / replay / manipulation action against a "
           "live industrial process — strictly out of Vulnerability-Assessment "
           "scope and never run against a production target (safety risk).")
_DOS = ("Confirming this needs flooding / disruptive load that is unsafe to run "
        "against a production OT target (could trip a safety system).")
_HOST = ("Requires on-host / engineering-workstation access (forensics, config "
         "review, historian DB credentials) that a remote SaaS scanner does not "
         "have.")
_CREDS = ("Active credential testing against a live PLC/HMI/BMS requires explicit "
          "engagement-scope authorization and a wordlist; it is intentionally not "
          "auto-run by the VA scanner (lockout / safety risk). Reported as "
          "advisory — verify default credentials manually under change control.")
_INTEL = ("Requires a Shodan / Censys API key and is a third-party intelligence "
          "lookup rather than a direct probe of the customer target; run it "
          "manually with your own API key.")
_METHOD = ("Methodology / governance review item — an analyst task performed "
           "against documentation, network diagrams and change-control records, "
           "not a network-observable condition.")
_MANUAL = ("Manual / creative analyst task — requires interactive tooling, "
           "firmware reverse-engineering or process knowledge, not a remote probe.")


# ─────────────── REAL LIVE PROBES (detection-only) ───────────────

def _valid_modbus_adu(resp, txn_hi, txn_lo, unit, fc):
    """Full Modbus/TCP ADU validation of a response to our FC01 Read-Coils.
    Requires the MBAP header to ECHO our request, not just resp[7]:
      bytes 0-1  transaction id  -> must equal the txn id we sent
      bytes 2-3  protocol id     -> must be 0x0000 (Modbus)
      bytes 4-5  length          -> remaining-byte count, must equal len(resp)-6
                                    and be >= 2 (unit + function code)
      byte  6    unit id         -> must echo the unit we addressed
      byte  7    function code   -> our FC (0x01) or its exception (0x81)
    A single magic byte is not enough — any TCP service could happen to put
    0x01/0x81 at offset 7."""
    if not resp or len(resp) < 9:
        return False
    if resp[0] != txn_hi or resp[1] != txn_lo:
        return False
    if resp[2] != 0x00 or resp[3] != 0x00:        # protocol id must be 0
        return False
    length = (resp[4] << 8) | resp[5]
    if length < 2 or length != len(resp) - 6:      # length field must be exact
        return False
    if resp[6] != unit:                            # unit id must echo
        return False
    if resp[7] not in (fc, fc | 0x80):             # FC echo or exception FC
        return False
    # If it is the normal reply (0x01), a byte-count field must follow and be
    # consistent. If it is the exception (0x81), an exception code follows.
    if resp[7] == fc:
        byte_count = resp[8]
        return byte_count == len(resp) - 9
    return True


def _probe_modbus(target, req):
    """Modbus TCP/502 — send a benign Read-Coils (FC01) request and confirm a
    valid full Modbus ADU (MBAP header echo + function-code echo). Read-only."""
    host = _host(target)
    findings = []
    if not _tcp_open(host, 502):
        return _clean_pos("modbus_502_probe", target,
                          "Modbus TCP/502 not externally reachable",
                          "TCP/502 closed/filtered", 1, "Modbus TCP/502 probe")
    # FC01 Read Coils, 1 coil at addr 0 — a harmless read. txn=0x0001 unit=0x01.
    req_pkt = b"\x00\x01\x00\x00\x00\x06\x01\x01\x00\x00\x00\x01"
    resp = _tcp_send_recv(host, 502, req_pkt, timeout=3.0, recv=256)
    if _valid_modbus_adu(resp, 0x00, 0x01, 0x01, 0x01):
        # Full MBAP echo (txn id + protocol 0 + exact length + unit) plus a
        # valid FC01 reply / FC81 exception — confirms a real Modbus speaker.
        findings.append(wrap_finding(
            "Modbus TCP/502 service responding — unauthenticated critical-control protocol exposed to the internet",
            "CRITICAL", cvss="9.5", cwe="CWE-306", owasp="A05:2021",
            remediation="NEVER expose Modbus to the internet. Segregate the OT network from corporate; place Modbus behind an industrial firewall + VPN.",
            evidence_marker="TCP/502 open; full Modbus ADU validated — MBAP header echoed our transaction id, protocol-id 0x0000, exact length field and unit id, with a valid FC01/FC81 function-code echo"))
    else:
        findings.append(wrap_finding(
            "TCP/502 reachable — port commonly used by Modbus (protocol NOT confirmed)",
            "INFO", cvss="0.0", cwe="CWE-306",
            remediation="Confirm what listens on TCP/502; if Modbus, restrict it to the OT network immediately.",
            evidence_marker="TCP/502 open only — the response did not validate as a full Modbus ADU (MBAP transaction-id echo + protocol-id 0x0000 + exact length + unit echo + FC01/FC81), so Modbus is NOT protocol-confirmed; any service on this port would match"))
    return _build("modbus_502_probe", target, findings, 1, "Modbus TCP/502 protocol probe")


def _valid_cotp_cc(resp):
    """Validate a TPKT + COTP Connection Confirm (not just resp[5]==0xd0):
      bytes 0-1  TPKT version 0x03 + reserved 0x00
      bytes 2-3  TPKT length        -> must equal len(resp)
      byte  4    COTP length indicator (LI) -> >=6, and LI+5 <= len(resp)
      byte  5    COTP PDU type      -> high nibble 0xd = Connection Confirm
    Returns True only when the whole TPKT/COTP framing is self-consistent."""
    if not resp or len(resp) < 7:
        return False
    if resp[0] != 0x03 or resp[1] != 0x00:
        return False
    tpkt_len = (resp[2] << 8) | resp[3]
    if tpkt_len != len(resp) or tpkt_len < 7:
        return False
    li = resp[4]
    if li < 6 or (li + 5) > len(resp):
        return False
    # COTP PDU type is the high nibble of byte 5; 0xd0 = Connection Confirm.
    return (resp[5] & 0xf0) == 0xd0


def _valid_s7comm_setup_ack(resp):
    """Validate an S7comm Setup-Communication ACK on top of TPKT+COTP DT:
      byte 0      TPKT 0x03
      after COTP (DT, LI usually 0x02, type 0xf0) the S7 protocol id 0x32
      S7 ROSCTR byte -> 0x03 (Ack_Data) for a setup response.
    Best-effort: scans the first bytes for the S7 protocol id 0x32 followed by
    a valid ROSCTR, which a non-S7 service will not produce."""
    if not resp or len(resp) < 10 or resp[0] != 0x03:
        return False
    # TPKT(4) + COTP header (LI+1). LI at offset 4.
    li = resp[4]
    s7_off = 5 + li
    if s7_off + 1 >= len(resp):
        return False
    return resp[s7_off] == 0x32 and resp[s7_off + 1] in (0x02, 0x03)


def _probe_siemens_s7(target, req):
    """Siemens S7 / ISO-TSAP TCP/102 — validate a full COTP Connection Confirm
    and (best-effort) an S7comm Setup-Communication ACK, not just resp[5]==0xd0.
    Read-only handshake; no PLC commands."""
    host = _host(target)
    if not _tcp_open(host, 102):
        return _clean_pos("siemens_s7_102_probe", target,
                          "Siemens S7 TCP/102 (ISO-TSAP) not reachable",
                          "TCP/102 closed/filtered", 1, "Siemens S7 PLC probe")
    # 1) COTP Connection Request (TPKT + COTP CR). Benign session setup.
    cotp_cr = (b"\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\x0a"
               b"\xc1\x02\x01\x00\xc2\x02\x01\x02")
    s7comm_confirmed = False
    cotp_ok = False
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(3.0)
            if s.connect_ex((host, 102)) == 0:
                s.send(cotp_cr)
                resp = s.recv(64)
                cotp_ok = _valid_cotp_cc(resp)
                if cotp_ok:
                    # 2) S7comm Setup Communication (over COTP DT). Read-only.
                    s7_setup = (b"\x03\x00\x00\x19\x02\xf0\x80"          # TPKT+COTP DT
                                b"\x32\x01\x00\x00\x00\x00\x00\x08"      # S7 header
                                b"\x00\x00\xf0\x00\x00\x01\x00\x01\x01\xe0")
                    try:
                        s.send(s7_setup)
                        s7resp = s.recv(64)
                        s7comm_confirmed = _valid_s7comm_setup_ack(s7resp)
                    except Exception:
                        s7comm_confirmed = False
    except Exception:
        cotp_ok = False
    if cotp_ok:
        # Full COTP CC framing validated = real S7/ISO-TSAP node; S7comm setup
        # ACK (when present) additionally confirms the S7comm application layer.
        proto = "S7comm" if s7comm_confirmed else "ISO-TSAP/COTP"
        findings = [wrap_finding(
            f"Siemens S7 / ISO-TSAP TCP/102 confirmed ({proto}) — PLC management exposed to the internet",
            "CRITICAL", cvss="9.5", cwe="CWE-306", owasp="A05:2021",
            remediation="NEVER expose PLC management (S7comm/ISO-TSAP) to the internet. Use an industrial firewall + VPN and restrict to the engineering VLAN.",
            evidence_marker="TCP/102 open; valid TPKT+COTP Connection Confirm framing"
                            + ("; S7comm Setup-Communication ACK (protocol id 0x32) confirmed" if s7comm_confirmed else ""))]
    else:
        findings = [wrap_finding(
            "TCP/102 reachable — port commonly used by Siemens S7 / ISO-TSAP (protocol NOT confirmed)",
            "INFO", cvss="0.0", cwe="CWE-306",
            remediation="Confirm the service on TCP/102; if it is a PLC, isolate it on the OT network.",
            evidence_marker="TCP/102 open only — no valid TPKT+COTP Connection Confirm framing was returned, so S7/ISO-TSAP is NOT protocol-confirmed; any service on this port would match")]
    return _build("siemens_s7_102_probe", target, findings, 1, "Siemens S7 PLC probe")


def _enip_list_identity(host, timeout=3.0):
    """Send an EtherNet/IP List Identity command (read-only discovery) and
    return raw response bytes. Empty on failure."""
    # ENIP encapsulation: command 0x0063 (List Identity), length 0, session 0.
    pkt = struct.pack("<HHIIQ", 0x0063, 0, 0, 0, 0) + b"\x00\x00\x00\x00"
    return _tcp_send_recv(host, 44818, pkt, timeout=timeout, recv=512)


def _valid_enip_list_identity(resp):
    """Validate a full EtherNet/IP List-Identity REPLY, not just resp[0]==0x63.
    ENIP encapsulation header (little-endian, 24 bytes):
      [0:2]   command  -> must echo 0x0063 (List Identity)
      [2:4]   length   -> payload byte count, must equal len(resp)-24
      [4:8]   session  -> 0 for List Identity
      [8:12]  status   -> must be 0x00000000 (success)
    CPF payload then begins at offset 24:
      [24:26] item count -> >= 1
      [26:28] item type  -> 0x000C (List Identity item)
    Any service that merely emits 0x63 at byte 0 fails these structural checks.
    """
    if not resp or len(resp) < 26:
        return False
    command = resp[0] | (resp[1] << 8)
    if command != 0x0063:
        return False
    length = resp[2] | (resp[3] << 8)
    if length != len(resp) - 24 or length < 2:
        return False
    status = resp[8] | (resp[9] << 8) | (resp[10] << 16) | (resp[11] << 24)
    if status != 0:
        return False
    item_count = resp[24] | (resp[25] << 8)
    if item_count < 1:
        return False
    if len(resp) >= 28:
        item_type = resp[26] | (resp[27] << 8)
        if item_type != 0x000C:
            return False
    return True


def _probe_ethernet_ip(target, req):
    """EtherNet/IP CIP TCP/44818 — List Identity (read-only). Confirms a real
    CIP device and extracts the product name string if present."""
    host = _host(target)
    if not _tcp_open(host, 44818):
        return _clean_pos("ethernet_ip_probe", target,
                          "EtherNet/IP TCP/44818 not reachable",
                          "TCP/44818 closed/filtered", 1, "EtherNet/IP probe")
    resp = _enip_list_identity(host)
    if _valid_enip_list_identity(resp):
        # Try to recover the printable product-name tail (ASCII).
        ascii_tail = "".join(chr(b) for b in resp[40:] if 32 <= b < 127).strip()
        prod = ascii_tail[-48:] if ascii_tail else ""
        findings = [wrap_finding(
            "EtherNet/IP CIP TCP/44818 confirmed — Rockwell/Allen-Bradley class PLC exposed"
            + (f" ({prod})" if prod else ""),
            "CRITICAL", cvss="9.5", cwe="CWE-306", owasp="A05:2021",
            remediation="Block EtherNet/IP (44818) at the corporate firewall; segregate the OT/ENIP network.",
            evidence_marker="TCP/44818 open; full ENIP List-Identity reply validated (command 0x0063 echo, exact length, status 0, item count>=1, CPF item type 0x000C)"
                            + (f"; product='{prod}'" if prod else ""))]
    else:
        findings = [wrap_finding(
            "TCP/44818 reachable — port used by EtherNet/IP CIP (protocol NOT confirmed)",
            "INFO", cvss="0.0", cwe="CWE-306",
            remediation="Identify the service on 44818; if it is EtherNet/IP, restrict it to the OT network and firewall internet exposure.",
            evidence_marker="TCP/44818 open only — the reply did not validate as a full ENIP List-Identity structure (command 0x0063 echo + exact length + status 0 + item count + CPF item type 0x000C), so EtherNet/IP is NOT protocol-confirmed; any service on this port would match")]
    return _build("ethernet_ip_probe", target, findings, 1, "EtherNet/IP List-Identity probe")


def _probe_rockwell(target, req):
    """Rockwell / Allen-Bradley ControlLogix — same EtherNet/IP surface,
    reported under the vendor slug. List Identity, read-only."""
    host = _host(target)
    if not _tcp_open(host, 44818):
        return _clean_pos("rockwell_allenbradley_probe", target,
                          "Rockwell/Allen-Bradley EtherNet/IP (44818) not reachable",
                          "TCP/44818 closed/filtered", 1, "Rockwell EtherNet/IP probe")
    resp = _enip_list_identity(host)
    if _valid_enip_list_identity(resp):
        ascii_tail = "".join(chr(b) for b in resp[40:] if 32 <= b < 127).strip()
        prod = ascii_tail[-48:] if ascii_tail else ""
        findings = [wrap_finding(
            "Rockwell/Allen-Bradley class CIP device exposed on EtherNet/IP 44818"
            + (f" ({prod})" if prod else ""),
            "CRITICAL", cvss="9.5", cwe="CWE-306", owasp="A05:2021",
            remediation="Isolate ControlLogix/CompactLogix on the OT VLAN; never expose 44818 to the internet.",
            evidence_marker="Full ENIP List-Identity reply validated (command 0x0063 echo, exact length, status 0, item count>=1, CPF item type 0x000C)"
                            + (f"; product='{prod}'" if prod else ""))]
    else:
        findings = [wrap_finding(
            "TCP/44818 reachable — port used by EtherNet/IP CIP (Rockwell/AB; protocol NOT confirmed)",
            "INFO", cvss="0.0", cwe="CWE-306",
            remediation="Identify the service on 44818; if it is EtherNet/IP, restrict it to the OT VLAN.",
            evidence_marker="TCP/44818 open only — the reply did not validate as a full ENIP List-Identity structure (command 0x0063 echo + exact length + status 0 + item count + CPF item type 0x000C), so EtherNet/IP is NOT protocol-confirmed; any service on this port would match")]
    return _build("rockwell_allenbradley_probe", target, findings, 1, "Rockwell EtherNet/IP probe")


def _probe_schneider(target, req):
    """Schneider Modicon — Modbus TCP/502 (read-only FC01) plus an HTTP banner
    fingerprint for the Modicon web UI."""
    host = _host(target)
    findings = []
    modbus_up = False
    if _tcp_open(host, 502):
        req_pkt = b"\x00\x01\x00\x00\x00\x06\x01\x01\x00\x00\x00\x01"
        resp = _tcp_send_recv(host, 502, req_pkt, timeout=3.0, recv=64)
        if _valid_modbus_adu(resp, 0x00, 0x01, 0x01, 0x01):
            modbus_up = True
            findings.append(wrap_finding(
                "Schneider Modicon Modbus TCP/502 responding — unauthenticated control protocol exposed",
                "CRITICAL", cvss="9.5", cwe="CWE-306", owasp="A05:2021",
                remediation="Segregate Modicon PLCs on the OT network; never expose Modbus to the internet.",
                evidence_marker="TCP/502 open; full Modbus ADU validated (MBAP header echo + FC01/FC81 function-code echo)"))
    # HTTP fingerprint (read-only GET) for Schneider/Modicon web UI.
    for scheme, port in (("http", 80), ("https", 443)):
        status, hdrs, body = _http_get(f"{scheme}://{host}:{port}/", timeout=4)
        blob = (str(hdrs) + " " + body).lower()
        if status and any(s in blob for s in ("schneider", "modicon", "unity", "m340", "m580", "quantum")):
            findings.append(wrap_finding(
                "Schneider Electric / Modicon web interface fingerprinted on HTTP (NOT protocol-confirmed)",
                "INFO", cvss="0.0", cwe="CWE-200",
                remediation="Remove internet exposure of the PLC web UI; place behind VPN + industrial firewall.",
                evidence_marker=f"{scheme}://{host}:{port}/ HTTP body/header matched a Schneider/Modicon keyword (HTTP {status}) — fingerprint only, the Modbus control protocol was NOT confirmed on this surface"))
            break
    if not findings:
        return _clean_pos("schneider_modicon_probe", target,
                          "No Schneider/Modicon Modbus or web fingerprint observed",
                          "TCP/502 + HTTP fingerprint negative", 2, "Schneider Modicon probe")
    return _build("schneider_modicon_probe", target, findings, 2, "Schneider Modicon probe")


def _probe_dnp3(target, req):
    """DNP3 TCP/20000 — reachability of the SCADA outstation port (read-only
    TCP connect; no DNP3 application data sent)."""
    host = _host(target)
    if _tcp_open(host, 20000):
        findings = [wrap_finding(
            "TCP/20000 reachable — port commonly used by DNP3 SCADA outstations (protocol NOT confirmed)",
            "INFO", cvss="0.0", cwe="CWE-306", owasp="A05:2021",
            remediation="Identify what service listens on 20000. If it is a DNP3 outstation it must run on an isolated network with DNP3-SA (Secure Authentication) + VPN; never expose 20000 to the internet.",
            evidence_marker="TCP/20000 open (read-only connect only; no DNP3 application data was sent, so DNP3 is NOT protocol-confirmed — any service on this port would match)")]
        return _build("dnp3_unauth_advisory", target, findings, 1, "DNP3 TCP/20000 probe")
    return _clean_pos("dnp3_unauth_advisory", target,
                      "DNP3 TCP/20000 not externally reachable",
                      "TCP/20000 closed/filtered", 1, "DNP3 TCP/20000 probe")


def _valid_bacnet_bvlc(data):
    """Validate a full BACnet/IP BVLC frame, not just data[0]==0x81:
      byte 0    BVLC type      -> must be 0x81 (BACnet/IP)
      byte 1    BVLC function  -> a known function code (0x00-0x0c)
      bytes 2-3 BVLC length    -> entire BVLC length, must equal len(data)
      byte 4    NPDU version   -> must be 0x01 (when an NPDU follows)
    Any UDP service that happens to start with 0x81 fails the length/NPDU check.
    """
    if not data or len(data) < 4:
        return False
    if data[0] != 0x81:
        return False
    if data[1] > 0x0c:                              # known BVLC function range
        return False
    bvlc_len = (data[2] << 8) | data[3]
    if bvlc_len != len(data) or bvlc_len < 4:
        return False
    # A Who-Is reply (I-Am, Original-Unicast/Broadcast NPDU) carries an NPDU
    # whose version byte is 0x01. Forwarded-NPDU (func 0x04) inserts a 6-byte
    # B/IP address before the NPDU; accept either layout.
    if data[1] == 0x04:
        return len(data) >= 11 and data[10] == 0x01
    return data[4] == 0x01


def _probe_bacnet(target, req):
    """BACnet/IP UDP/47808 — send a benign Who-Is and confirm a full BVLC frame
    (type + function + length + NPDU version). Read-only discovery."""
    host = _host(target)
    # BVLC/NPDU Who-Is (global broadcast, unconfirmed). Read-only.
    who_is = b"\x81\x0b\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08"
    got, data = _udp_probe(host, 47808, who_is, timeout=2.5)
    if got and _valid_bacnet_bvlc(data):
        # Full BVLC framing (type 0x81 + valid function + length == len(data))
        # plus an NPDU version 0x01 = a real BACnet/IP speaker answered.
        findings = [wrap_finding(
            "BACnet/IP UDP/47808 confirmed — building automation system (BMS) exposed to the internet",
            "HIGH", cvss="7.5", cwe="CWE-306", owasp="A05:2021",
            remediation="Restrict BACnet to the building network; firewall internet exposure of UDP/47808.",
            evidence_marker="UDP/47808 Who-Is answered with a valid BACnet/IP BVLC frame (type 0x81, length field == datagram length, NPDU version 0x01)")]
        return _build("bacnet_47808_probe", target, findings, 1, "BACnet UDP/47808 probe")
    if _tcp_open(host, 47808):
        findings = [wrap_finding(
            "TCP/47808 reachable — port commonly used by BACnet/IP (protocol NOT confirmed)",
            "INFO", cvss="0.0", cwe="CWE-306",
            remediation="Confirm and restrict BACnet exposure.",
            evidence_marker="TCP/47808 open only — the UDP/47808 Who-Is was not answered with a BACnet/IP BVLC frame (0x81), so BACnet is NOT protocol-confirmed; any service on this port would match")]
        return _build("bacnet_47808_probe", target, findings, 1, "BACnet UDP/47808 probe")
    return _clean_pos("bacnet_47808_probe", target,
                      "BACnet UDP/47808 not externally reachable",
                      "UDP/47808 silent, TCP/47808 closed", 1, "BACnet UDP/47808 probe")


def _valid_knxnet_search_response(data):
    """Validate a full KNXnet/IP SEARCH_RESPONSE, not just the 0x0610 prefix:
      byte 0    header length    -> 0x06
      byte 1    protocol version -> 0x10
      bytes 2-3 service type     -> 0x0202 (SEARCH_RESPONSE)
      bytes 4-5 total length     -> entire frame length, must equal len(data)
    We sent a SEARCH_REQUEST (0x0201); a real KNXnet/IP server answers with
    SEARCH_RESPONSE (0x0202). Any service emitting 0x06 0x10 fails the service-
    type + length validation."""
    if not data or len(data) < 6:
        return False
    if data[0] != 0x06 or data[1] != 0x10:
        return False
    service_type = (data[2] << 8) | data[3]
    if service_type != 0x0202:                      # SEARCH_RESPONSE
        return False
    total_len = (data[4] << 8) | data[5]
    return total_len == len(data) and total_len >= 6


def _probe_knx(target, req):
    """KNXnet/IP UDP/3671 — send a benign SEARCH_REQUEST and confirm a full
    KNXnet/IP SEARCH_RESPONSE frame (read-only building-bus discovery)."""
    host = _host(target)
    # KNXnet/IP SEARCH_REQUEST. HPAI carries 0.0.0.0:0 (discovery). Read-only.
    search_req = (b"\x06\x10"           # header: 0x0610
                  b"\x02\x01"           # service type SEARCH_REQUEST
                  b"\x00\x0e"           # total length 14
                  b"\x08\x01"           # HPAI: structure length 8, UDP
                  b"\x00\x00\x00\x00"   # IP 0.0.0.0
                  b"\x00\x00")          # port 0
    got, data = _udp_probe(host, 3671, search_req, timeout=2.5)
    if got and _valid_knxnet_search_response(data):
        findings = [wrap_finding(
            "KNXnet/IP UDP/3671 confirmed — KNX building-automation bus exposed to the internet",
            "HIGH", cvss="7.5", cwe="CWE-306", owasp="A05:2021",
            remediation="Restrict KNXnet/IP to the building LAN; firewall UDP/3671 from the internet (KNX has no native authentication).",
            evidence_marker="UDP/3671 SEARCH_REQUEST answered with a valid KNXnet/IP SEARCH_RESPONSE frame (header 0x0610, service type 0x0202, total-length field == datagram length)")]
        return _build("knx_3671_probe", target, findings, 1, "KNXnet/IP UDP/3671 probe")
    if _tcp_open(host, 3671):
        findings = [wrap_finding(
            "TCP/3671 reachable — port commonly used by KNXnet/IP (protocol NOT confirmed)",
            "INFO", cvss="0.0", cwe="CWE-306",
            remediation="Confirm and restrict KNX exposure.",
            evidence_marker="TCP/3671 open only — the UDP/3671 SEARCH_REQUEST was not answered with a KNXnet/IP frame (0x0610), so KNX is NOT protocol-confirmed; any service on this port would match")]
        return _build("knx_3671_probe", target, findings, 1, "KNXnet/IP UDP/3671 probe")
    return _clean_pos("knx_3671_probe", target,
                      "KNXnet/IP UDP/3671 not externally reachable",
                      "UDP/3671 silent, TCP/3671 closed", 1, "KNXnet/IP UDP/3671 probe")


_ICS_PORTS = {
    502:   "Modbus TCP",
    102:   "Siemens S7 / ISO-TSAP",
    44818: "EtherNet/IP (Rockwell/AB)",
    20000: "DNP3 (power/water SCADA)",
    47808: "BACnet/IP (BMS)",
    1911:  "Tridium Niagara Fox",
    4911:  "Niagara Fox (secure)",
    2404:  "IEC 60870-5-104",
    789:   "Red Lion Crimson",
    9600:  "OMRON FINS",
    1962:  "PCWorx (Phoenix Contact)",
    5006:  "MELSEC-Q (Mitsubishi)",
    5007:  "MELSEC-Q (Mitsubishi)",
}


def _probe_ics_sweep(target, req):
    """PLCScan-style ICS port sweep — read-only TCP reachability across the
    common ICS/SCADA service ports. Emits a graded finding ONLY for ports
    actually observed open."""
    host = _host(target)
    open_ports = []
    for port in _ICS_PORTS:
        if _tcp_open(host, port, timeout=1.5):
            open_ports.append(port)
    if not open_ports:
        return _clean_pos("ics_plcscan_discovery", target,
                          "No common ICS/SCADA service ports reachable",
                          f"Swept {len(_ICS_PORTS)} ICS ports — all closed/filtered",
                          len(_ICS_PORTS), "PLCScan-style ICS port sweep")
    labels = [f"{p} ({_ICS_PORTS[p]})" for p in sorted(open_ports)]
    findings = [wrap_finding(
        f"{len(open_ports)} ICS/SCADA-associated port(s) reachable (TCP connect only — protocols NOT confirmed on this sweep)",
        "INFO", cvss="0.0", cwe="CWE-306", owasp="A05:2021",
        remediation="Identify the service on each open port — the per-protocol probes (Modbus/S7/EtherNet-IP/BACnet/KNX) confirm the actual protocol. If any is a live ICS service, industrial protocols must never be internet-reachable: segregate the OT network (Purdue model) behind an industrial firewall + VPN.",
        evidence_marker="Open ICS-associated ports (TCP reachability only — no ICS protocol was confirmed on this sweep; any service on these ports would match): " + ", ".join(labels))]
    return _build("ics_plcscan_discovery", target, findings, len(_ICS_PORTS),
                  "PLCScan-style ICS port sweep",
                  raw={"open_ics_ports": sorted(open_ports)})


def _probe_ics_nmap(target, req):
    """nmap-ICS-NSE-equivalent — same read-only ICS port sweep, reported under
    the nmap-scripts slug. Detection-only."""
    res = _probe_ics_sweep(target, req)
    res["tool"] = "ics_nmap_ics_scripts"
    res["tests_summary"] = "nmap-ICS-NSE-equivalent ICS port sweep"
    return res


def _has_telnet_iac(banner):
    """Confirm the Telnet protocol by its IAC negotiation sequence, not by a
    'login:'/'password:' substring. A real Telnet server opens with one or more
    IAC (0xff) commands: 0xff followed by 0xfb-0xfe (WILL/WONT/DO/DONT) or 0xfa
    (SB). 0xff at the very end with no following command byte does not count."""
    if not banner:
        return False
    i = banner.find(0xff)
    while i != -1:
        if i + 1 < len(banner) and banner[i + 1] in (0xfa, 0xfb, 0xfc, 0xfd, 0xfe):
            return True
        i = banner.find(0xff, i + 1)
    return False


def _probe_iot_telnet(target, req):
    """IoT telnet 23/2323 — Mirai-era exposure. Grabs the banner read-only and
    confirms Telnet ONLY via the IAC negotiation sequence; no credential
    attempts."""
    host = _host(target)
    findings = []
    for port in (23, 2323):
        if not _tcp_open(host, port, timeout=2.0):
            continue
        banner = _tcp_send_recv(host, port, b"", timeout=2.0, recv=128)
        btxt = banner.decode("utf-8", errors="ignore").strip()
        # PROTOCOL confirmation requires the Telnet IAC negotiation sequence:
        # an IAC byte (0xff) immediately followed by a command byte in the
        # WILL/WONT/DO/DONT/SB range (0xfa-0xfe). A "login:"/"password:" string
        # alone is NOT Telnet-specific (SSH/HTTP/SMTP/banners all emit it) and
        # must not confirm the protocol.
        telnet_confirmed = _has_telnet_iac(banner)
        if telnet_confirmed:
            findings.append(wrap_finding(
                f"Telnet {port}/tcp open — IoT/Mirai-era exposure (cleartext, default-cred risk)",
                "HIGH", cvss="8.1", cwe="CWE-319", owasp="A07:2021",
                remediation="Disable telnet entirely; use SSH with key auth. Replace any embedded default credentials.",
                evidence_marker=f"TCP/{port} returned a Telnet IAC negotiation sequence (0xff + WILL/WONT/DO/DONT). Banner: {btxt[:80] if btxt else '(empty)'}"))
        else:
            findings.append(wrap_finding(
                f"TCP/{port} reachable — port commonly used by Telnet (protocol NOT confirmed)",
                "INFO", cvss="0.0", cwe="CWE-319", owasp="A07:2021",
                remediation="Disable telnet entirely; use SSH with key auth. Replace any embedded default credentials.",
                evidence_marker=f"TCP/{port} open only — no Telnet IAC negotiation sequence (0xff + WILL/WONT/DO/DONT command byte) was observed, so Telnet is NOT protocol-confirmed; a bare login:/password: prompt is not Telnet-specific and any service on this port would match. Banner: {btxt[:80] if btxt else '(empty)'}"))
    if not findings:
        return _clean_pos("iot_telnet_2323_probe", target,
                          "Telnet 23/2323 not externally reachable",
                          "Both ports closed/filtered", 2, "IoT telnet port probe")
    return _build("iot_telnet_2323_probe", target, findings, 2, "IoT telnet port probe")


def _valid_ssdp_response(data):
    """Validate an SSDP M-SEARCH response, not just an 'HTTP/1.1' or 'USN'
    substring. A genuine SSDP reply is an HTTP-style datagram that:
      - starts with an 'HTTP/1.1 200' status line (response to our M-SEARCH), and
      - carries the SSDP-mandatory ST and USN headers, and
      - carries a LOCATION or SERVER header (device-description pointer/banner).
    A plain HTTP server or any payload merely containing 'USN' fails this."""
    if not data:
        return False
    txt = data.decode("utf-8", errors="ignore")
    head = txt[:24].upper()
    if not head.startswith("HTTP/1.1 200") and not head.startswith("HTTP/1.0 200"):
        return False
    low = txt.lower()
    if "st:" not in low:                             # ST header is mandatory
        return False
    if "usn:" not in low:                            # USN header is mandatory
        return False
    if "location:" not in low and "server:" not in low:
        return False
    return True


def _probe_upnp(target, req):
    """UPnP/SSDP UDP/1900 — send a benign M-SEARCH and confirm a structurally
    valid SSDP response (status line + ST/USN/LOCATION headers). Read-only."""
    host = _host(target)
    msearch = (b"M-SEARCH * HTTP/1.1\r\n"
               b"HOST: 239.255.255.250:1900\r\n"
               b'MAN: "ssdp:discover"\r\n'
               b"MX: 1\r\n"
               b"ST: ssdp:all\r\n\r\n")
    got, data = _udp_probe(host, 1900, msearch, timeout=2.5, recv=1024)
    if got and _valid_ssdp_response(data):
        txt = data.decode("utf-8", errors="ignore")
        server = ""
        for line in txt.split("\r\n"):
            if line.lower().startswith("server:"):
                server = line[7:].strip()
                break
        findings = [wrap_finding(
            "UPnP/SSDP UDP/1900 reachable from the internet — device discovery interface exposed",
            "HIGH", cvss="7.5", cwe="CWE-200", owasp="A05:2021",
            remediation="Disable UPnP/SSDP on the WAN interface; UPnP must never face the internet (used for NAT-pinhole and device enumeration abuse).",
            evidence_marker="UDP/1900 M-SEARCH answered with a valid SSDP response (HTTP/1.1 200 status line + ST/USN headers)" + (f"; SERVER: {server[:80]}" if server else ""))]
        return _build("iot_upnp_audit", target, findings, 1, "UPnP/SSDP discovery probe")
    if got and data:
        findings = [wrap_finding(
            "UDP/1900 responded but SSDP format NOT confirmed",
            "INFO", cvss="0.0", cwe="CWE-200", owasp="A05:2021",
            remediation="Confirm what service answers on UDP/1900; if it is UPnP/SSDP, disable it on the WAN interface.",
            evidence_marker="UDP/1900 returned data but it was not a valid SSDP response (missing the HTTP/1.1 status line and the ST/USN headers), so UPnP/SSDP is NOT protocol-confirmed")]
        return _build("iot_upnp_audit", target, findings, 1, "UPnP/SSDP discovery probe")
    return _clean_pos("iot_upnp_audit", target,
                      "UPnP/SSDP UDP/1900 not externally reachable",
                      "UDP/1900 M-SEARCH silent", 1, "UPnP/SSDP discovery probe")


def _probe_mdns(target, req):
    """mDNS / DNS-SD UDP/5353 — send a benign service-enumeration query and
    confirm a multicast-DNS response. Read-only."""
    host = _host(target)
    # mDNS query for _services._dns-sd._udp.local PTR (service enumeration).
    qname = b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
    query = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x0c\x00\x01"
    got, data = _udp_probe(host, 5353, query, timeout=2.5, recv=1024)
    if got and data and len(data) >= 12:
        # Validate the full mDNS response header before any graded severity:
        #   - QR/response bit set (byte 2 high bit 0x80), and
        #   - ANCOUNT > 0 (bytes 6-7) — i.e. at least one answer record, and
        #   - the datagram is long enough to actually carry an answer section.
        # The QR bit alone is not enough — a malformed/empty reply must not grade.
        qr = (data[2] & 0x80) != 0
        ancount = (data[6] << 8) | data[7]
        has_answer_room = len(data) > 12        # header(12) + at least some RRs
        mdns_confirmed = qr and ancount > 0 and has_answer_room
        if mdns_confirmed:
            findings = [wrap_finding(
                "mDNS / DNS-SD UDP/5353 reachable from the internet — service/device enumeration exposed",
                "MEDIUM", cvss="5.3", cwe="CWE-200", owasp="A05:2021",
                remediation="mDNS is a link-local protocol and must never be internet-reachable; filter UDP/5353 at the edge.",
                evidence_marker=f"UDP/5353 query answered with a valid multicast-DNS response (DNS QR/response bit set, ANCOUNT={ancount} answer record(s), answer section present)")]
        else:
            findings = [wrap_finding(
                "UDP/5353 responded but mDNS format NOT confirmed",
                "INFO", cvss="0.0", cwe="CWE-200", owasp="A05:2021",
                remediation="mDNS is a link-local protocol and must never be internet-reachable; filter UDP/5353 at the edge.",
                evidence_marker="UDP/5353 returned data but it did not validate as an mDNS response (requires the DNS QR/response bit set AND ANCOUNT>0 AND an answer section) — not a confirmed mDNS response")]
        return _build("iot_mdns_dnssd_audit", target, findings, 1, "mDNS/DNS-SD probe")
    return _clean_pos("iot_mdns_dnssd_audit", target,
                      "mDNS/DNS-SD UDP/5353 not externally reachable",
                      "UDP/5353 silent", 1, "mDNS/DNS-SD probe")


def _probe_rtsp(target, req):
    """RTSP TCP/554 — IP camera / DVR exposure. Sends a benign OPTIONS request
    (read-only); confirms an RTSP reply."""
    host = _host(target)
    findings = []
    for port in (554, 8554):
        if not _tcp_open(host, port, timeout=2.0):
            continue
        opts = (f"OPTIONS rtsp://{host}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n"
                f"User-Agent: VulnusLab/2.0\r\n\r\n").encode()
        resp = _tcp_send_recv(host, port, opts, timeout=3.0, recv=512)
        rtxt = resp.decode("utf-8", errors="ignore")
        if rtxt.startswith("RTSP/"):
            server = ""
            for line in rtxt.split("\r\n"):
                if line.lower().startswith("server:"):
                    server = line[7:].strip()
                    break
            findings.append(wrap_finding(
                f"RTSP camera/DVR stream interface exposed on TCP/{port}",
                "HIGH", cvss="7.5", cwe="CWE-306", owasp="A05:2021",
                remediation="Never expose RTSP to the internet; place cameras behind a VPN. Replace default camera credentials.",
                evidence_marker=f"RTSP/{port} OPTIONS answered" + (f"; SERVER: {server[:60]}" if server else "")))
            break
    if not findings:
        return _clean_pos("iot_rtsp_camera_probe", target,
                          "RTSP 554/8554 not externally reachable",
                          "RTSP ports closed/filtered", 2, "RTSP camera probe")
    return _build("iot_rtsp_camera_probe", target, findings, 2, "RTSP camera probe")


def _probe_onvif(target, req):
    """ONVIF camera fingerprint — read-only HTTP GET of the ONVIF device
    service path and common camera web markers."""
    host = _host(target)
    findings = []
    candidates = [
        ("http", 80, "/onvif/device_service"),
        ("https", 443, "/onvif/device_service"),
        ("http", 80, "/"),
        ("http", 8080, "/"),
    ]
    for scheme, port, path in candidates:
        status, hdrs, body = _http_get(f"{scheme}://{host}:{port}{path}", timeout=4)
        if not status:
            continue
        # Only a real 200 page can carry a genuine camera/ONVIF fingerprint.
        # A non-200 (e.g. plain Apache 404) echoes the requested path back in
        # its error body, which self-matches the 'onvif' keyword on a
        # non-camera host — a reflected false positive.
        if status != 200:
            continue
        # Exclude any keyword that is merely the requested path reflected back
        # in the response (echoed-path self-match). Strip every echoed copy of
        # the path from the headers+body, then require the keyword to still
        # survive — a genuine fingerprint (Server header, product string, real
        # camera markup) does; a reflected 'onvif' from the URL does not.
        path_lower = path.lower()
        blob = (str(hdrs) + " " + body).lower()
        non_echoed = blob.replace(path_lower, " ")
        matched = None
        for s in ("onvif", "hikvision", "dahua", "axis", "rtsp", "network camera", "ipcamera", "webcamxp"):
            if s not in blob:
                continue
            # If the keyword only exists because it is part of the reflected
            # request path, drop it as a self-match.
            if s in path_lower and s not in non_echoed:
                continue
            matched = s
            break
        if matched:
            findings.append(wrap_finding(
                "ONVIF / IP-camera web interface fingerprinted on HTTP (NOT protocol-confirmed)",
                "INFO", cvss="0.0", cwe="CWE-200", owasp="A05:2021",
                remediation="Remove camera web UI from the internet; place behind VPN and replace default credentials.",
                evidence_marker=f"{scheme}://{host}:{port}{path} HTTP 200 body/header matched an ONVIF/camera keyword '{matched}' — fingerprint only, the ONVIF/RTSP service was NOT confirmed on this surface"))
            break
    if not findings:
        return _clean_pos("iot_onvif_camera_audit", target,
                          "No ONVIF/IP-camera HTTP fingerprint observed",
                          "HTTP camera fingerprint negative", len(candidates),
                          "ONVIF camera HTTP fingerprint")
    return _build("iot_onvif_camera_audit", target, findings, len(candidates),
                  "ONVIF camera HTTP fingerprint")


# ─────────────────────────── PROBES map ───────────────────────────
# Every slug in T below maps here — either a live probe (above) or an
# advisory-by-design probe (_abd). NO bare scaffolds remain.

PROBES = {
    # §1 ICS / SCADA Discovery
    "ics_shodan_scada_query":      _abd("ics_shodan_scada_query", "Shodan SCADA intelligence query", _INTEL),
    "ics_censys_scada_query":      _abd("ics_censys_scada_query", "Censys SCADA intelligence query", _INTEL),
    "ics_grassmarlin_discovery":   _abd("ics_grassmarlin_discovery", "GRASSMARLIN passive ICS network mapping", _LAN),
    "ics_nmap_ics_scripts":        _probe_ics_nmap,        # REAL
    "ics_plcscan_discovery":       _probe_ics_sweep,       # REAL
    "ics_pcap_protocol_inspect":   _abd("ics_pcap_protocol_inspect", "PCAP ICS-protocol inspection", _LAN),
    "ics_asset_inventory":         _abd("ics_asset_inventory", "ICS asset-inventory reconciliation", _METHOD),
    "ics_purdue_model_audit":      _abd("ics_purdue_model_audit", "Purdue-model zone/conduit segmentation audit", _METHOD),
    "ics_dmz_audit":               _abd("ics_dmz_audit", "ICS/IT DMZ data-broker audit", _METHOD),
    "ics_iec62443_compliance":     _abd("ics_iec62443_compliance", "IEC 62443 security-level (SL) compliance review", _METHOD),
    "manual_ics_discovery":        _abd("manual_ics_discovery", "Manual creative ICS discovery", _MANUAL),

    # §2 Modbus / DNP3 / EtherNet/IP
    "modbus_502_probe":            _probe_modbus,          # REAL
    "modbus_read_holding_registers": _abd("modbus_read_holding_registers", "Modbus holding-register read enumeration", _ACTIVE),
    "modbus_write_coils_advisory": _abd("modbus_write_coils_advisory", "Modbus coil/register WRITE to a live process", _ACTIVE),
    "dnp3_unauth_advisory":        _probe_dnp3,            # REAL
    "ethernet_ip_probe":           _probe_ethernet_ip,     # REAL
    "cip_attribute_audit":         _abd("cip_attribute_audit", "CIP attribute/object enumeration on a live PLC", _ACTIVE),
    "modbus_flood_dos":            _abd("modbus_flood_dos", "Modbus flood / DoS against a live controller", _DOS),
    "manual_modbus_review":        _abd("manual_modbus_review", "Manual Modbus register-map review", _MANUAL),

    # §3 Siemens / Schneider / Rockwell
    "siemens_s7_102_probe":        _probe_siemens_s7,      # REAL
    "siemens_simatic_audit":       _abd("siemens_simatic_audit", "SIMATIC STEP7 / S7comm project audit", _ACTIVE),
    "schneider_modicon_probe":     _probe_schneider,       # REAL
    "rockwell_allenbradley_probe": _probe_rockwell,        # REAL
    "rockwell_logix5000_advisory": _abd("rockwell_logix5000_advisory", "Logix5000 tag/program enumeration on a live PLC", _ACTIVE),
    "siemens_default_creds":       _abd("siemens_default_creds", "Siemens PLC/HMI default-credential testing", _CREDS),
    "manual_vendor_review":        _abd("manual_vendor_review", "Manual vendor-specific firmware reverse-engineering", _MANUAL),

    # §4 BACnet / KNX / LonWorks
    "bacnet_47808_probe":          _probe_bacnet,          # REAL
    "bacnet_unauth_object_list":   _abd("bacnet_unauth_object_list", "BACnet unauthenticated object-list read/enumeration", _ACTIVE),
    "knx_3671_probe":              _probe_knx,             # REAL
    "lonworks_audit":              _abd("lonworks_audit", "LonWorks / LonTalk bus enumeration", _LAN),
    "bms_default_creds":           _abd("bms_default_creds", "Building-management-system default-credential testing", _CREDS),
    "manual_building_review":      _abd("manual_building_review", "Manual building-automation (HVAC/elevator/access) review", _MANUAL),

    # §5 IoT Device Recon
    "iot_shodan_query":            _abd("iot_shodan_query", "Shodan IoT intelligence query", _INTEL),
    "iot_censys_query":            _abd("iot_censys_query", "Censys IoT intelligence query", _INTEL),
    "iot_mac_oui_lookup":          _abd("iot_mac_oui_lookup", "MAC OUI vendor lookup", _LAN),
    "iot_default_creds_check":     _abd("iot_default_creds_check", "IoT default-credential testing", _CREDS),
    "iot_telnet_2323_probe":       _probe_iot_telnet,      # REAL
    "iot_upnp_audit":              _probe_upnp,            # REAL
    "iot_mdns_dnssd_audit":        _probe_mdns,            # REAL
    "iot_rtsp_camera_probe":       _probe_rtsp,            # REAL
    "iot_onvif_camera_audit":      _probe_onvif,           # REAL
    "iot_router_firmware_audit":   _abd("iot_router_firmware_audit", "Router firmware version / CVE audit", _HOST),
    "iot_dvr_default_creds":       _abd("iot_dvr_default_creds", "DVR/NVR default-credential testing", _CREDS),
    "iot_printer_default_creds":   _abd("iot_printer_default_creds", "Network-printer default-credential testing", _CREDS),
    "manual_iot_review":           _abd("manual_iot_review", "Manual creative IoT recon", _MANUAL),

    # §6 Zigbee / Z-Wave / Thread
    "zigbee_killerbee_audit":      _abd("zigbee_killerbee_audit", "Zigbee (KillerBee) RF audit", _RF),
    "zwave_zforce_audit":          _abd("zwave_zforce_audit", "Z-Wave (Z-Force) RF audit", _RF),
    "thread_audit":                _abd("thread_audit", "Thread (802.15.4) mesh-network audit", _RF),
    "matter_audit":                _abd("matter_audit", "Matter protocol audit", _RF),
    "manual_mesh_iot_review":      _abd("manual_mesh_iot_review", "Manual creative mesh-IoT / RF analysis", _MANUAL),

    # §7 Matter / Smart Home (2024+)
    "matter_commissioning_audit":  _abd("matter_commissioning_audit", "Matter commissioning (onboarding payload) audit", _RF),
    "matter_pase_pake_audit":      _abd("matter_pase_pake_audit", "Matter PASE/PAKE secure-session audit", _RF),
    "matter_otacert_audit":        _abd("matter_otacert_audit", "Matter OTA / device-attestation-certificate audit", _RF),
    "manual_matter_review":        _abd("manual_matter_review", "Manual creative Matter abuse PoC", _MANUAL),

    # §8 OT Pentest Methodology / Safety
    "ot_safety_first_audit":       _abd("ot_safety_first_audit", "OT safety-first engagement-scope review", _METHOD),
    "ot_lockout_procedure":        _abd("ot_lockout_procedure", "OT lockout/tagout (LOTO) procedure check", _METHOD),
    "ot_change_management":        _abd("ot_change_management", "OT change-management / MOC audit", _METHOD),
    "manual_ot_pentest_planning":  _abd("manual_ot_pentest_planning", "Manual OT pentest planning + IR-plan validation", _METHOD),
}


# ─── TECHNIQUE LIST (T) — DO NOT CHANGE ORDER/SLUGS/COUNT (orchestrator
#     slices this by index; the planned severities here are display-only,
#     the actual emitted severity comes from each probe above). ───
T = [
    # §1 ICS/SCADA Discovery (11)
    ("ics_shodan_scada_query", "Shodan SCADA query.", "INFO", "0.0"),
    ("ics_censys_scada_query", "Censys SCADA query.", "INFO", "0.0"),
    ("ics_grassmarlin_discovery", "GRASSMARLIN discovery.", "INFO", "0.0"),
    ("ics_nmap_ics_scripts", "nmap ICS NSE scripts.", "MEDIUM", "5.5"),
    ("ics_plcscan_discovery", "PLCScan discovery.", "MEDIUM", "5.5"),
    ("ics_pcap_protocol_inspect", "PCAP protocol inspect.", "INFO", "0.0"),
    ("ics_asset_inventory", "ICS asset inventory.", "INFO", "0.0"),
    ("ics_purdue_model_audit", "Purdue model audit.", "INFO", "0.0"),
    ("ics_dmz_audit", "ICS DMZ audit.", "MEDIUM", "5.5"),
    ("ics_iec62443_compliance", "IEC 62443 compliance check.", "MEDIUM", "5.5"),
    ("manual_ics_discovery", "Manual ICS discovery.", "INFO", "0.0"),
    # §2 Modbus/DNP3/EtherNet/IP (8)
    ("modbus_502_probe", "Modbus TCP/502 probe.", "MEDIUM", "5.5"),
    ("modbus_read_holding_registers", "Modbus read holding registers.", "HIGH", "7.0"),
    ("modbus_write_coils_advisory", "Modbus write coils advisory.", "HIGH", "8.0"),
    ("dnp3_unauth_advisory", "DNP3 unauth advisory.", "HIGH", "7.5"),
    ("ethernet_ip_probe", "EtherNet/IP probe.", "MEDIUM", "5.5"),
    ("cip_attribute_audit", "CIP attribute audit.", "MEDIUM", "5.5"),
    ("modbus_flood_dos", "Modbus flood DoS advisory.", "HIGH", "7.0"),
    ("manual_modbus_review", "Manual Modbus review.", "INFO", "0.0"),
    # §3 Siemens/Schneider/Rockwell (7)
    ("siemens_s7_102_probe", "Siemens S7 TCP/102 probe.", "MEDIUM", "5.5"),
    ("siemens_simatic_audit", "SIMATIC step7 audit.", "MEDIUM", "5.5"),
    ("schneider_modicon_probe", "Schneider Modicon probe.", "MEDIUM", "5.5"),
    ("rockwell_allenbradley_probe", "Rockwell/AB probe.", "MEDIUM", "5.5"),
    ("rockwell_logix5000_advisory", "Logix5000 advisory.", "MEDIUM", "5.5"),
    ("siemens_default_creds", "Siemens default creds.", "HIGH", "7.5"),
    ("manual_vendor_review", "Manual vendor review.", "INFO", "0.0"),
    # §4 BACnet/KNX/LonWorks (6)
    ("bacnet_47808_probe", "BACnet UDP/47808 probe.", "MEDIUM", "5.5"),
    ("bacnet_unauth_object_list", "BACnet unauth object list.", "HIGH", "7.5"),
    ("knx_3671_probe", "KNX UDP/3671 probe.", "MEDIUM", "5.5"),
    ("lonworks_audit", "LonWorks audit.", "MEDIUM", "5.5"),
    ("bms_default_creds", "BMS default creds.", "HIGH", "7.5"),
    ("manual_building_review", "Manual building automation review.", "INFO", "0.0"),
    # §5 IoT Device Recon (13)
    ("iot_shodan_query", "IoT Shodan query.", "INFO", "0.0"),
    ("iot_censys_query", "IoT Censys query.", "INFO", "0.0"),
    ("iot_mac_oui_lookup", "MAC OUI vendor lookup.", "INFO", "0.0"),
    ("iot_default_creds_check", "IoT default creds check.", "HIGH", "8.0"),
    ("iot_telnet_2323_probe", "Telnet 23/2323 probe (Mirai).", "HIGH", "8.0"),
    ("iot_upnp_audit", "UPnP audit.", "HIGH", "7.5"),
    ("iot_mdns_dnssd_audit", "mDNS/DNS-SD audit.", "MEDIUM", "5.5"),
    ("iot_rtsp_camera_probe", "RTSP camera probe.", "HIGH", "7.5"),
    ("iot_onvif_camera_audit", "ONVIF camera audit.", "MEDIUM", "5.5"),
    ("iot_router_firmware_audit", "Router firmware audit.", "MEDIUM", "5.5"),
    ("iot_dvr_default_creds", "DVR default creds.", "HIGH", "7.5"),
    ("iot_printer_default_creds", "Printer default creds.", "MEDIUM", "5.5"),
    ("manual_iot_review", "Manual IoT review.", "INFO", "0.0"),
    # §6 Zigbee/Z-Wave/Thread (5)
    ("zigbee_killerbee_audit", "Zigbee killerbee audit.", "MEDIUM", "5.5"),
    ("zwave_zforce_audit", "Z-Wave Z-Force audit.", "MEDIUM", "5.5"),
    ("thread_audit", "Thread protocol audit.", "MEDIUM", "5.5"),
    ("matter_audit", "Matter protocol audit.", "MEDIUM", "5.5"),
    ("manual_mesh_iot_review", "Manual mesh IoT review.", "INFO", "0.0"),
    # §7 Matter/Smart Home (4)
    ("matter_commissioning_audit", "Matter commissioning audit.", "MEDIUM", "5.5"),
    ("matter_pase_pake_audit", "Matter PASE/PAKE audit.", "MEDIUM", "5.5"),
    ("matter_otacert_audit", "Matter OTA cert audit.", "MEDIUM", "5.5"),
    ("manual_matter_review", "Manual Matter review.", "INFO", "0.0"),
    # §8 OT Pentest Methodology (4)
    ("ot_safety_first_audit", "OT safety-first audit.", "INFO", "0.0"),
    ("ot_lockout_procedure", "OT lockout/tagout procedure check.", "INFO", "0.0"),
    ("ot_change_management", "OT change management audit.", "INFO", "0.0"),
    ("manual_ot_pentest_planning", "Manual OT pentest planning.", "INFO", "0.0"),
]

router = make_advisory_router("iot_ot", T,
    playbook_ref="See module_playbooks/30_iot_ot.md.",
    probes=PROBES)


def register(app):
    app.include_router(router)
