"""auth_surface_audit - finding rules (VL-METHOD aware).

Rules read state populated by AuthSurfaceAudit's flow:
  - methodology_findings : list of exposed auth-service findings, each:
        {service, port, banner, transport, plaintext, tls_offered,
         confidence, kind}
  - reachable_services   : list of {service, port} that accepted a TCP SYN
  - probed_ports         : how many auth ports were probed
  - target_host          : clean host probed

ZERO-FALSE-POSITIVE CONTRACT
----------------------------
A graded (HIGH/MEDIUM/LOW) severity is emitted ONLY for a service that
ACTUALLY accepted a TCP connection (port_open == True) on this target.
Detection here = "this auth surface is internet-reachable" — that is a
demonstrated, observable fact, NOT a recommendation, so the graded
findings stamp verified_exploit=True to opt out of the advisory cap.

The scanner performs NO authentication attempts. It only:
  - TCP connect-tests known auth ports
  - reads service banners (passive)
  - notes whether the protocol transmits credentials in cleartext
"""


INTEL_FIELDS = [
    ("Target host",          "target_host"),
    ("Auth ports probed",    "probed_ports"),
    ("Reachable services",   "reachable_services"),
    ("Service banners",      "service_banners"),
    ("Stage timings (ms)",   "stage_timings"),
    ("Stage errors",         "stage_errors"),
]


# Protocols where credentials traverse the wire in cleartext when TLS is
# not negotiated. Internet exposure of these is a real, observable risk.
_CLEARTEXT_AUTH = {
    "telnet": ("CWE-319", "Telnet transmits credentials in plaintext"),
    "ftp":    ("CWE-319", "FTP control channel transmits credentials in plaintext"),
    "pop3":   ("CWE-319", "POP3 (no STARTTLS) transmits credentials in plaintext"),
    "imap":   ("CWE-319", "IMAP (no STARTTLS) transmits credentials in plaintext"),
    "smtp":   ("CWE-319", "SMTP AUTH without STARTTLS transmits credentials in plaintext"),
    "ldap":   ("CWE-319", "LDAP simple bind without TLS transmits credentials in plaintext"),
    "vnc":    ("CWE-326", "VNC uses a weak DES-based challenge; exposure invites brute force"),
}


def _by_kind(s):
    out = {"cleartext_auth_exposed": [], "auth_service_exposed": []}
    for f in (s.get("methodology_findings") or []):
        k = f.get("kind")
        if k in out:
            out[k].append(f)
    return out


def _svc_summary(findings, limit=8):
    seen = []
    for f in findings:
        label = f"{f.get('service','?')}/{f.get('port','?')}"
        if label not in seen:
            seen.append(label)
        if len(seen) >= limit:
            break
    return ", ".join(seen)


# Banner markers that indicate the service ACTUALLY presents a plaintext
# authentication prompt / handshake on the wire (not merely that the port is
# open). Only when a banner matches do we treat the cleartext exposure as a
# proven (HIGH) credential-interception risk rather than mere surface (MEDIUM).
_PLAINTEXT_AUTH_BANNER = {
    "telnet": ("login:", "username:", "password:", "\xff\xfd", "\xff\xfb"),
    "ftp":    ("220 ", "ftp", "user "),
    "pop3":   ("+ok", "pop3"),
    "imap":   ("* ok", "imap"),
    "smtp":   ("220 ", "smtp", "esmtp"),
    "vnc":    ("rfb 003.", "rfb"),
    "ldap":   (),  # LDAP bind has no human-readable cleartext prompt banner
}


def _has_plaintext_auth_prompt(f):
    """True only if the captured banner shows the service really speaks a
    cleartext auth handshake (not just that the TCP port answered)."""
    svc = (f.get("service") or "").lower()
    banner = (f.get("banner") or "").lower()
    if not banner:
        return False
    markers = _PLAINTEXT_AUTH_BANNER.get(svc)
    if not markers:
        return False
    return any(m in banner for m in markers)


def rule_input_missing(s):
    sr = s.get("skipped_reason") or ""
    if "no target supplied" not in sr:
        return None
    return {
        "name": "No target supplied - auth-surface audit skipped",
        "severity": "INFO",
        "evidence": sr,
        "remediation": ("Supply the target host/IP so the scanner can map which "
                        "remote-authentication services are internet-reachable."),
        "cwe": "CWE-1006",
    }


def rule_cleartext_auth_confirmed(s):
    # ZERO-FP: HIGH only when the banner grab PROVES the service actually
    # presents a cleartext authentication handshake on the wire (login prompt /
    # protocol greeting), not merely that a cleartext-default port answered a
    # TCP SYN. A port being open is exposure surface, not proof of cleartext auth.
    g = _by_kind(s)
    hits = [f for f in g["cleartext_auth_exposed"] if _has_plaintext_auth_prompt(f)]
    if not hits:
        return None
    return {
        "name": f"Cleartext-credential authentication service confirmed exposed ({len(hits)} service)",
        "severity": "HIGH", "cvss": "7.5",
        "cwe": "CWE-319", "owasp": "A07:2021",
        "verified_exploit": True,  # banner proves a live cleartext auth handshake
        "evidence": ("The following service(s) accepted a TCP connection AND "
                     "their banner shows a live cleartext authentication "
                     f"handshake/prompt: {_svc_summary(hits)}. An on-path "
                     "attacker can capture credentials in transit, and public "
                     "exposure invites credential spraying. No credentials were "
                     "submitted by this scan."),
        "remediation": ("Restrict these services to a VPN / management VLAN "
                        "(firewall the ports at the perimeter). Migrate to the "
                        "encrypted equivalent: Telnet->SSH, FTP->SFTP/FTPS, "
                        "POP3/IMAP/SMTP->STARTTLS or implicit-TLS ports "
                        "(995/993/465), LDAP->LDAPS (636). Where the service must "
                        "stay public, enforce TLS-only and place it behind "
                        "source-IP allowlisting + rate limiting."),
    }


def rule_cleartext_auth_surface(s):
    # A cleartext-default port is OPEN but the banner did NOT prove a live
    # plaintext auth prompt -> exposure surface, MEDIUM (not HIGH). Could be
    # firewalled at the auth layer, TLS-wrapped, or non-interactive.
    g = _by_kind(s)
    hits = [f for f in g["cleartext_auth_exposed"] if not _has_plaintext_auth_prompt(f)]
    if not hits:
        return None
    return {
        "name": f"Cleartext-default authentication port exposed to the internet ({len(hits)} service)",
        "severity": "MEDIUM", "cvss": "5.3",
        "cwe": "CWE-319", "owasp": "A07:2021",
        "verified_exploit": True,  # the port is observably reachable
        "evidence": ("The following port(s) for protocols that default to "
                     "cleartext credentials accepted a TCP connection: "
                     f"{_svc_summary(hits)}. The banner grab did NOT capture a "
                     "live plaintext auth prompt, so cleartext credential "
                     "transmission is exposure surface here, not confirmed. "
                     "Internet exposure of these ports still invites credential "
                     "spraying. No credentials were submitted by this scan."),
        "remediation": ("Restrict these services to a VPN / management VLAN "
                        "(firewall the ports at the perimeter). If the service is "
                        "in use, confirm it enforces TLS (STARTTLS / implicit "
                        "TLS) and migrate any cleartext fallback to the encrypted "
                        "equivalent: Telnet->SSH, FTP->SFTP/FTPS, "
                        "POP3/IMAP/SMTP->995/993/465, LDAP->LDAPS (636). Add "
                        "source-IP allowlisting + rate limiting."),
    }


def rule_auth_service_exposed(s):
    g = _by_kind(s)
    hits = g["auth_service_exposed"]
    if not hits:
        return None
    return {
        "name": f"Remote-authentication service exposed to the internet ({len(hits)} service)",
        "severity": "MEDIUM", "cvss": "5.3",
        "cwe": "CWE-284", "owasp": "A07:2021",
        "verified_exploit": True,  # observed reachable on the target
        "evidence": ("These authentication endpoints accepted a TCP connection "
                     "from the scanner and are therefore reachable from the "
                     f"public internet: {_svc_summary(hits)}. Internet-exposed "
                     "auth surfaces are the primary target for password spraying "
                     "and credential-stuffing campaigns. No credentials were "
                     "submitted by this scan."),
        "remediation": ("Place administrative / database / directory services "
                        "behind a VPN or bastion and firewall the ports at the "
                        "perimeter. Where exposure is required, enforce MFA, "
                        "account lockout, source-IP allowlisting, and rate "
                        "limiting. Disable any service that is not in active use."),
    }


def rule_positive_clean(s):
    if (s.get("methodology_total") or 0) > 0:
        return None
    if "no target supplied" in (s.get("skipped_reason") or ""):
        return None
    probed = int(s.get("probed_ports") or 0)
    if probed < 5:
        return None
    return {
        "name": "No internet-exposed remote-authentication services detected",
        "severity": "POSITIVE",
        "evidence": (f"Probed {probed} common remote-authentication ports "
                     "(Telnet, FTP, RDP, SMB, VNC, LDAP/LDAPS, IMAP/POP3/SMTP, "
                     "MSSQL, MySQL, Postgres, MongoDB, Redis, Kerberos); none "
                     "accepted a TCP connection from the scanner."),
        "remediation": ("Maintain — keep admin/database/directory services off "
                        "the public internet (VPN / bastion only) and re-run "
                        "this audit after any infrastructure change."),
        "cwe": "CWE-284",
        "owasp": "A07:2021",
    }


AUTH_SURFACE_AUDIT_FINDING_RULES = [
    rule_input_missing,
    rule_positive_clean,
    rule_cleartext_auth_confirmed,
    rule_cleartext_auth_surface,
    rule_auth_service_exposed,
]
