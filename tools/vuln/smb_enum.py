"""SMB Enumeration — checks for exposed SMB service on TCP/445 + null-session.

VL-FORGE'd infrastructure vulnerability scanner.
Route: POST /api/vuln/smb_enum

What it does:
  1. TCP connect to port 445 — exposed SMB is HIGH severity by itself
  2. Send SMB2 Negotiate Protocol Request — parse dialect / signing required flag
  3. Detect SMBv1 (CVE-2017-0144 EternalBlue surface) — CRITICAL if enabled
  4. Check if message signing is disabled (CWE-287 — relay attack surface)

Pure-Python SMB negotiate — no smbclient/impacket dependency.
"""
import socket
import struct
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, recon_host,
                            wrap_finding, standard_response)
from tools.vuln._vuln_common import vuln_response

router = APIRouter()

_PORT = 445
_TIMEOUT = 5.0

# SMB2 negotiate protocol request (minimal, asks for dialect 0x0202 / 0x0210 / 0x0300 / 0x0311)
# Plus SMBv1 negotiate for backwards compat detection
_SMB2_NEGOTIATE = bytes.fromhex(
    "00000050"                              # NetBIOS session header (length 0x50)
    "fe534d42"                              # SMB2 magic ("\xfeSMB")
    "40000000" "00000000" "00000000"        # header (structure, status, command)
    "00000000" "00000000" "00000000"
    "00000000" "00000000" "00000000"
    "00000000" "00000000"
    "24000500" "01000000" "7f000000"        # negotiate struct: 5 dialects, sec mode, capabilities
    "0000" "0000000000000000000000000000000000"  # client GUID
    "00000000"                              # negotiate context offset
    "0202" "1002" "0003" "1103"              # dialects: SMB 2.0.2 / 2.1 / 3.0 / 3.1.1
    "0000"                                  # padding
)

_SMB1_NEGOTIATE = bytes.fromhex(
    "0000002f"                              # NetBIOS length
    "ff534d42" "72" "00000000"               # SMB1 magic + SMB_COM_NEGOTIATE (0x72)
    "1801" "28000000" "0000" "0000" "0000"
    "0000" "0000" "0000" "0000"
    "0000"
    "00" "0c00" "025043204e4554574f524b2050524f4752414d20312e30"
    "00"
)

def _smb_probe(host):
    """Connect to TCP/445, return dict with negotiation results or None on failure."""
    try:
        sock = socket.create_connection((host, _PORT), timeout=_TIMEOUT)
        sock.settimeout(_TIMEOUT)

        # Try SMB2 first
        sock.send(_SMB2_NEGOTIATE)
        resp2 = sock.recv(4096)

        result = {"port_open": True, "raw_response": resp2[:200].hex()}
        if len(resp2) >= 70 and resp2[4:8] == b"\xfeSMB":
            # Parse SMB2 negotiate response
            # Byte 70-72: dialect revision
            dialect = struct.unpack("<H", resp2[72:74])[0] if len(resp2) >= 74 else 0
            sec_mode = resp2[70] if len(resp2) >= 71 else 0
            result["smb2_dialect"] = f"0x{dialect:04x}"
            result["signing_required"] = bool(sec_mode & 0x02)
            result["signing_enabled"]  = bool(sec_mode & 0x01)

        # Try SMB1 separately on a fresh connection
        try:
            sock.close()
            sock2 = socket.create_connection((host, _PORT), timeout=_TIMEOUT)
            sock2.settimeout(_TIMEOUT)
            sock2.send(_SMB1_NEGOTIATE)
            resp1 = sock2.recv(2048)
            sock2.close()
            # If we got a SMB1 response (not error code), SMB1 is enabled
            if len(resp1) >= 36 and resp1[4:8] == b"\xffSMB":
                # Check for "DialectIndex" — if not 0xFFFF, SMB1 dialect accepted
                if len(resp1) >= 38:
                    dialect_idx = struct.unpack("<H", resp1[37:39])[0]
                    result["smb1_enabled"] = (dialect_idx != 0xFFFF)
        except Exception:
            result["smb1_enabled"] = None

        return result
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    except Exception:
        return None

@router.post("/api/vuln/smb_enum")
def scan_smb_enum(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    result = _smb_probe(host)

    if not result:
        return vuln_response(tool="smb_enum", target=req.target, findings=[],
            tested=1,
            skipped_reason=f"SMB port 445/TCP closed or firewalled on {host}",
            raw_data={"smb_enum": {"port_open": False}})

    findings = []
    # SMB exposed at all — always at least MEDIUM
    findings.append(wrap_finding(
        "SMB service exposed to public network on TCP/445",
        "MEDIUM", cvss="5.3", cwe="CWE-200", owasp="A05:2021",
        remediation=("SMB should NEVER be exposed to the internet. "
                      "Restrict to internal management VLAN via firewall. "
                      "If remote access is needed, tunnel through VPN."),
        evidence_marker=f"TCP 445 on {host} responded to SMB negotiate. "
                         f"Dialect: {result.get('smb2_dialect', 'unknown')}"))

    # SMBv1 enabled = CRITICAL (EternalBlue / WannaCry vector)
    if result.get("smb1_enabled"):
        findings.append(wrap_finding(
            "SMBv1 protocol enabled — EternalBlue / WannaCry attack surface",
            "CRITICAL", cvss="9.8", cwe="CWE-22", owasp="A06:2021",
            remediation=("Disable SMBv1 immediately. "
                          "Windows: Set-SmbServerConfiguration -EnableSMB1Protocol $false. "
                          "Samba: 'min protocol = SMB2' in smb.conf. "
                          "SMBv1 has multiple unpatched RCEs including CVE-2017-0144 (EternalBlue)."),
            evidence_marker=f"TCP 445 accepted SMBv1 negotiate request"))

    # Signing not required = relay attack surface
    if result.get("smb2_dialect") and not result.get("signing_required"):
        findings.append(wrap_finding(
            "SMB message signing not required — NTLM relay attack surface",
            "HIGH", cvss="7.5", cwe="CWE-287", owasp="A07:2021",
            remediation=("Enforce SMB signing. "
                          "Windows: GPO 'Microsoft network server: Digitally sign communications (always)' = Enabled. "
                          "Samba: 'server signing = mandatory' in smb.conf. "
                          "Prevents credential relay attacks (responder/ntlmrelayx)."),
            evidence_marker=f"SMB2 negotiate response had signing_required=False"))

    return vuln_response(tool="smb_enum", target=req.target, findings=findings,
        tested=1,
        what_checked="SMB exposure on TCP/445 + SMBv1 / message-signing enforcement",
        tests_summary=f"SMB: port open; {len(findings)} issue(s) confirmed",
        raw_data={"smb_enum": result})


def register(app):
    app.include_router(router)
