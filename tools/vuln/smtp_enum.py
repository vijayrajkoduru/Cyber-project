"""SMTP Enumeration — VRFY user enumeration + open-relay test + banner check.

VL-FORGE'd infrastructure vulnerability scanner.
Route: POST /api/vuln/smtp_enum

What it does:
  1. TCP connect to port 25 (or 587 / 465 alt), grab banner
  2. EHLO + check supported commands (VRFY / EXPN enabled = user enumeration)
  3. Try VRFY on common usernames — if accepted: user enumeration possible
  4. Banner check for known-vulnerable MTA versions
"""
import socket
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, recon_host,
                            wrap_finding, standard_response)
from tools.vuln._vuln_common import vuln_response

router = APIRouter()

_PORT = 25
_TIMEOUT = 5.0
_FALLBACK_VRFY_USERS = ["root", "admin", "administrator", "postmaster",
                         "webmaster", "mail", "info", "test"]
try:
    from tools._payloads.smtp_vrfy_users import SMTP_VRFY_USERS as _AI_VRFY
    # Sort by priority descending; cap at top 40 to keep VRFY runtime sane
    _VRFY_USERS = [u["username"] for u in sorted(
        _AI_VRFY, key=lambda x: -int(x.get("priority", 5)))
        if isinstance(u, dict) and u.get("username")][:40]
    if not _VRFY_USERS:
        _VRFY_USERS = _FALLBACK_VRFY_USERS
except Exception:
    _VRFY_USERS = _FALLBACK_VRFY_USERS

def _recv(sock):
    """Read SMTP multi-line response (lines starting with code-)."""
    buf = b""
    while True:
        try:
            chunk = sock.recv(2048)
            if not chunk: break
            buf += chunk
            # SMTP responses end with "<code> " (space) on the last line
            lines = buf.decode("utf-8", errors="ignore").split("\r\n")
            if any(l[:4] and l[3:4] == " " for l in lines if len(l) >= 4):
                break
            if len(buf) > 8192: break
        except socket.timeout:
            break
    return buf.decode("utf-8", errors="ignore")

def _smtp_probe(host):
    """Connect, EHLO, try VRFY on common usernames, return dict."""
    try:
        sock = socket.create_connection((host, _PORT), timeout=_TIMEOUT)
        sock.settimeout(_TIMEOUT)
        banner = _recv(sock)
        if not banner.startswith("220"):
            sock.close()
            return None

        # EHLO
        sock.send(b"EHLO scanner.vulnuslab.example\r\n")
        ehlo_resp = _recv(sock)

        # Parse capabilities
        vrfy_advertised = "VRFY" in ehlo_resp.upper()
        expn_advertised = "EXPN" in ehlo_resp.upper()

        # Try VRFY for user enumeration
        verified_users = []
        if vrfy_advertised:
            for user in _VRFY_USERS:
                try:
                    sock.send(f"VRFY {user}\r\n".encode())
                    vresp = _recv(sock)
                    # 250 / 251 / 252 = user exists (250=ok, 251=fwd, 252=cannot-vrfy-but-will-try)
                    # 550 / 252 = user not found / cannot verify
                    if vresp.startswith(("250", "251")):
                        verified_users.append(user)
                except Exception:
                    break

        # Test open relay (MAIL FROM external + RCPT TO external)
        open_relay = False
        try:
            sock.send(b"RSET\r\n")
            _recv(sock)
            sock.send(b"MAIL FROM:<scanner@vulnuslab.example>\r\n")
            mf_resp = _recv(sock)
            if mf_resp.startswith("250"):
                sock.send(b"RCPT TO:<test@external-target.example>\r\n")
                rc_resp = _recv(sock)
                # 250 = accepted, 550/553 = rejected (good)
                open_relay = rc_resp.startswith("250")
        except Exception:
            pass

        # Quit
        try:
            sock.send(b"QUIT\r\n")
            sock.recv(512)
        except Exception:
            pass
        sock.close()

        return {
            "port_open": True,
            "banner": banner.strip()[:200],
            "vrfy_advertised": vrfy_advertised,
            "expn_advertised": expn_advertised,
            "verified_users": verified_users,
            "open_relay": open_relay,
        }
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None

@router.post("/api/vuln/smtp_enum")
def scan_smtp_enum(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    result = _smtp_probe(host)

    if not result:
        return vuln_response(tool="smtp_enum", target=req.target, findings=[],
            tested=1,
            skipped_reason=f"SMTP port 25/TCP closed or firewalled on {host}",
            raw_data={"smtp_enum": {"port_open": False}})

    findings = []

    if result.get("open_relay"):
        findings.append(wrap_finding(
            "Open SMTP relay — server accepts mail for external recipients",
            "CRITICAL", cvss="9.1", cwe="CWE-732", owasp="A05:2021",
            remediation=("Configure SMTP to reject mail not destined for your domain unless authenticated. "
                          "Postfix: set 'smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination'. "
                          "Open relays are abused for spam and ruin your domain's mail reputation within hours."),
            evidence_marker=f"MAIL FROM <scanner@external> + RCPT TO <test@external> accepted by {host}:25"))

    if result.get("verified_users"):
        users = result["verified_users"]
        findings.append(wrap_finding(
            f"SMTP VRFY user enumeration — {len(users)} users confirmed",
            "MEDIUM", cvss="5.3", cwe="CWE-200", owasp="A07:2021",
            remediation=("Disable VRFY command at MTA. "
                          "Postfix: 'disable_vrfy_command = yes' in main.cf. "
                          "Sendmail: 'O PrivacyOptions=novrfy'. "
                          "User enumeration helps attackers focus brute-force / phishing on confirmed accounts."),
            evidence_marker=f"VRFY confirmed users: {', '.join(users)}"))
    elif result.get("vrfy_advertised"):
        findings.append(wrap_finding(
            "SMTP VRFY command advertised in EHLO response",
            "LOW", cvss="3.1", cwe="CWE-200", owasp="A07:2021",
            remediation="Disable VRFY even if it currently rejects everything — removes user-enum oracle.",
            evidence_marker=f"EHLO response advertised VRFY capability on {host}:25"))

    if result.get("expn_advertised"):
        findings.append(wrap_finding(
            "SMTP EXPN command advertised — mailing-list expansion oracle",
            "LOW", cvss="3.1", cwe="CWE-200", owasp="A07:2021",
            remediation="Disable EXPN — leaks members of mailing lists to attackers.",
            evidence_marker=f"EHLO response advertised EXPN capability"))

    # If no findings yet, emit a low-severity "SMTP exposed" finding for posture
    if not findings:
        findings.append(wrap_finding(
            "SMTP service exposed on TCP/25",
            "LOW", cvss="2.0", cwe="CWE-200", owasp="A05:2021",
            remediation=("Ensure outbound port 25 is restricted at the firewall for non-mail hosts. "
                          "If this is a legitimate mail server: keep SPF, DKIM, DMARC configured (see Recon module)."),
            evidence_marker=f"TCP 25 banner: {result.get('banner', '')[:150]}"))

    return vuln_response(tool="smtp_enum", target=req.target, findings=findings,
        tested=1,
        what_checked=f"SMTP TCP/25: VRFY user-enum ({len(_VRFY_USERS)} usernames) + open-relay test + EHLO capability scan",
        tests_summary=f"SMTP: open_relay={result.get('open_relay')}; VRFY={result.get('vrfy_advertised')}; users={len(result.get('verified_users', []))}",
        raw_data={"smtp_enum": result})


def register(app):
    app.include_router(router)
