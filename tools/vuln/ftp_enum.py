"""FTP Enumeration — banner grab + anonymous login check on TCP/21.

VL-FORGE'd infrastructure vulnerability scanner.
Route: POST /api/vuln/ftp_enum

What it does:
  1. TCP connect to port 21, grab banner
  2. Attempt anonymous login (USER anonymous / PASS anonymous@vulnuslab.example)
  3. If accepted: HIGH finding (anonymous FTP — data exfiltration / drive-by uploads)
  4. Parse banner for known-vulnerable versions (vsftpd 2.3.4 backdoor, ProFTPD 1.3.5 mod_copy, etc.)
"""
import socket
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, recon_host,
                            wrap_finding, standard_response)
from tools.vuln._vuln_common import vuln_response

router = APIRouter()

_PORT = 21
_TIMEOUT = 5.0

# Known-vulnerable FTP server versions (banner substring -> finding)
_VULN_BANNERS = [
    ("vsFTPd 2.3.4",       "CRITICAL", "9.8", "CVE-2011-2523",
     "vsftpd 2.3.4 backdoor — smiley-face login triggers root shell on port 6200",
     "Upgrade vsftpd immediately. The 2.3.4 release was compromised on the upstream mirror."),
    ("ProFTPD 1.3.5",      "HIGH",     "9.1", "CVE-2015-3306",
     "ProFTPD 1.3.5 mod_copy CPFR/CPTO arbitrary file copy — pre-auth RCE",
     "Upgrade ProFTPD to 1.3.5b or later. Disable mod_copy if not strictly needed."),
    ("WU-FTPD 2.6.0",      "CRITICAL", "9.0", "CVE-2000-0573",
     "WU-FTPD 2.6.0 SITE EXEC remote root vulnerability",
     "Replace WU-FTPD entirely — abandoned upstream since 2004. Use vsftpd or pure-ftpd."),
    ("Pure-FTPd",          "INFO",     "0.0", None,
     "Pure-FTPd detected — typically well-maintained but verify version",
     "Confirm version >= 1.0.49 and review authentication backend."),
]

def _recv_line(sock):
    """Read one CRLF-terminated FTP response."""
    buf = b""
    while not buf.endswith(b"\r\n"):
        try:
            chunk = sock.recv(1024)
            if not chunk: break
            buf += chunk
            if len(buf) > 4096: break
        except socket.timeout:
            break
    return buf.decode("utf-8", errors="ignore").strip()

def _ftp_probe(host):
    """Connect, grab banner, try anonymous login. Returns dict or None."""
    try:
        sock = socket.create_connection((host, _PORT), timeout=_TIMEOUT)
        sock.settimeout(_TIMEOUT)
        banner = _recv_line(sock)

        # Try anonymous login
        anon_ok = False
        try:
            sock.send(b"USER anonymous\r\n")
            user_resp = _recv_line(sock)
            if user_resp.startswith(("331", "230")):
                sock.send(b"PASS anonymous@vulnuslab.example\r\n")
                pass_resp = _recv_line(sock)
                anon_ok = pass_resp.startswith("230")
        except Exception:
            pass

        # Quit cleanly
        try:
            sock.send(b"QUIT\r\n")
            sock.recv(256)
        except Exception:
            pass
        sock.close()

        return {"port_open": True, "banner": banner, "anonymous_login": anon_ok}
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None

@router.post("/api/vuln/ftp_enum")
def scan_ftp_enum(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    result = _ftp_probe(host)

    if not result:
        return vuln_response(tool="ftp_enum", target=req.target, findings=[],
            tested=1,
            skipped_reason=f"FTP port 21/TCP closed or firewalled on {host}",
            raw_data={"ftp_enum": {"port_open": False}})

    findings = []
    banner = result.get("banner", "")

    # FTP exposed at all → at least LOW (plaintext credentials transit if used)
    findings.append(wrap_finding(
        "FTP service exposed on TCP/21 (plaintext protocol)",
        "LOW", cvss="3.1", cwe="CWE-319", owasp="A02:2021",
        remediation=("FTP transmits credentials and data in plaintext. "
                      "Use SFTP (port 22) or FTPS (port 990) instead. "
                      "If legacy FTP is required, restrict by IP allow-list."),
        evidence_marker=f"TCP 21 banner: {banner[:150]}"))

    # Anonymous login = HIGH
    if result.get("anonymous_login"):
        findings.append(wrap_finding(
            "Anonymous FTP login accepted",
            "HIGH", cvss="7.5", cwe="CWE-287", owasp="A07:2021",
            remediation=("Disable anonymous FTP access. "
                          "vsftpd: anonymous_enable=NO in /etc/vsftpd.conf. "
                          "ProFTPD: remove 'User anonymous' or set 'DenyAll' in <Anonymous> block. "
                          "Anonymous FTP is a known attack surface for drive-by uploads, "
                          "warez hosting, and as a staging area for further attacks."),
            evidence_marker=f"USER anonymous + PASS anonymous@.. returned 230 OK on {host}:21"))

    # Vulnerable banner check
    for substring, sev, cvss, cve, title, fix in _VULN_BANNERS:
        if substring.lower() in banner.lower() and sev != "INFO":
            findings.append(wrap_finding(
                title,
                sev, cvss=cvss, cwe="CWE-78", owasp="A06:2021",
                remediation=fix,
                evidence_marker=f"FTP banner contains {substring!r}: {banner[:150]}" + (f" ({cve})" if cve else "")))

    return vuln_response(tool="ftp_enum", target=req.target, findings=findings,
        tested=1,
        what_checked="FTP exposure on TCP/21 + anonymous login + vulnerable-version banner match",
        tests_summary=f"FTP: port open; banner='{banner[:80]}'; anon={result.get('anonymous_login')}",
        raw_data={"ftp_enum": result})


def register(app):
    app.include_router(router)
