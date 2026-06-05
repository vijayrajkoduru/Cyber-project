"""ftp_brute - finding rules (VL-METHOD aware).

Created 2026-06-05 modeled exactly on hydra_ssh_spray_findings.py for
the FTP password-spray scanner. Reads state keys populated by
FtpBrute's 7-stage flow:

  - methodology_findings  : list of verified credentials
  - port_reachable        : bool from pre_flight
  - fingerprint           : dict {banner, server, allows_anonymous}
  - chain_next            : list of follow-up scanner names

Severity derives from CONFIRMED + privilege_level:
  CONFIRMED admin (file_write_capable) -> CRITICAL CVSS 9.8
  CONFIRMED user                       -> MEDIUM   CVSS 6.5
  CONFIRMED guest                      -> LOW      CVSS 4.3
  SUSPECTED any                        -> LOW      CVSS 3.7
"""


INTEL_FIELDS = [
    ("FTP Banner",                "fingerprint"),
    ("Quick-probe attempts",      "quick_probe_attempts"),
    ("Quick-probe hits",          "quick_probe_hits"),
    ("Deep scan attempts",        "ftp_deep_attempts"),
    ("Stage timings (ms)",        "stage_timings"),
    ("Stage errors",              "stage_errors"),
    ("Chain ID",                  "chain_id"),
]


def rule_unreachable(s):
    if s.get("port_reachable") is not False:
        return None
    return {
        "name": "FTP port unreachable - cannot test credential security",
        "severity": "INFO",
        "evidence": s.get("skipped_reason") or "Port 21 closed or filtered",
        "remediation": ("If FTP is meant to be exposed, verify firewall + ftpd is "
                        "running. If FTP is intentionally blocked (recommended - "
                        "FTP is plaintext), this is good. Re-run scan once FTP is "
                        "reachable to actually test credential strength."),
        "cwe": "CWE-1006",
    }


def rule_input_missing(s):
    deep_skipped = s.get("deep_skipped") or ""
    if "userlist/passlist not supplied" not in deep_skipped:
        return None
    hits = s.get("methodology_total", 0)
    if hits > 0:
        return None
    return {
        "name": "Deep spray skipped - userlist/passlist not provided",
        "severity": "INFO",
        "evidence": ("Quick-probe ran 5 known-bad defaults (anonymous/anonymous@..., "
                     "ftp/ftp, admin/admin, root/root, test/test) - none worked. To "
                     "run a full spray, provide options.userlist + options.passlist "
                     "on the request body (newline-separated). Max 10 users x 25 pwds."),
        "remediation": ("Supply options.userlist + options.passlist to test against "
                        "your organization's password policy (or a known-leaked "
                        "wordlist like rockyou-top-100)."),
        "cwe": "CWE-1006",
    }


def rule_anonymous_enabled(s):
    """FTP anonymous login is enabled. Even if read-only, anonymous FTP
    in production violates least-privilege and historically leads to
    data exposure (anonymous user reads dropbox/uploads/backup dirs)."""
    fp = s.get("fingerprint") or {}
    if not fp.get("allows_anonymous"):
        return None
    return {
        "name": "Anonymous FTP login is enabled",
        "severity": "MEDIUM", "cvss": "5.3",
        "cwe": "CWE-287", "owasp": "A07:2021",
        "evidence": ("Server accepted anonymous login (user='anonymous'). "
                     f"Banner: {fp.get('banner', 'n/a')[:120]}. Anonymous FTP "
                     "lets unauthenticated attackers list any world-readable "
                     "directory on the server, which often leaks backups, "
                     "release artifacts, or staging databases."),
        "remediation": ("Disable anonymous login in your FTP server config: "
                        "vsftpd -> 'anonymous_enable=NO' in /etc/vsftpd.conf; "
                        "ProFTPD -> remove the <Anonymous> block; FileZilla "
                        "Server -> remove the 'anonymous' user. If anonymous "
                        "FTP is required for a legitimate public-download use "
                        "case, restrict to a chroot'd, read-only directory "
                        "containing only the files you intend to publish."),
    }


def _ftp_responded(s) -> bool:
    """True if FTP fingerprint actually got a 220 welcome banner from a
    real ftpd. An empty banner/server means filtered-accept firewall or
    non-FTP service squatting on port 21."""
    fp = s.get("fingerprint") or {}
    return bool(fp.get("banner") or fp.get("server"))


def rule_positive_quick(s):
    if s.get("methodology_total", 0) > 0:
        return None
    if s.get("port_reachable") is not True:
        return None
    if s.get("quick_probe_attempts", 0) == 0:
        return None
    if not _ftp_responded(s):
        return None  # no banner -> rule_inconclusive
    fp = s.get("fingerprint") or {}
    return {
        "name": "FTP rejects all 5 known-bad default credentials",
        "severity": "POSITIVE",
        "evidence": (f"Tried {s.get('quick_probe_attempts', 5)} known-bad defaults "
                     f"(anonymous/anonymous@, ftp/ftp, admin/admin, root/root, "
                     f"test/test); all rejected. FTP banner: "
                     f"{fp.get('server') or fp.get('banner') or 'unknown'}"),
        "remediation": ("Continue blocking default credentials. Stronger still: "
                        "replace FTP with SFTP/FTPS (FTP is plaintext over the "
                        "wire). Disable anonymous login in the ftpd config."),
        "cwe": "CWE-521",
        "owasp": "A07:2021",
    }


def rule_inconclusive(s):
    """Port accepts TCP SYN but no FTP 220 banner emerged - filtered-accept
    firewall or non-FTP service on port 21. Emit INFO so PDF doesn't
    falsely claim 'FTP rejects defaults' when we never spoke FTP."""
    if s.get("methodology_total", 0) > 0:
        return None
    if s.get("port_reachable") is not True:
        return None
    if s.get("quick_probe_attempts", 0) == 0:
        return None
    if _ftp_responded(s):
        return None
    return {
        "name": "FTP port reachable but no banner returned - credential security UNVERIFIED",
        "severity": "INFO",
        "evidence": (f"TCP/21 accepted the connection but no FTP 220 welcome "
                     f"banner was received and {s.get('quick_probe_attempts', 5)} "
                     "ftplib default-credential attempts errored/timed-out. "
                     "This is typical of stateful firewalls that 'accept-and-RST' "
                     "filtered ports or a non-FTP service squatting on port 21. "
                     "We cannot claim credentials are strong - we never reached "
                     "ftpd."),
        "remediation": ("If this host is supposed to expose FTP, verify ftpd is "
                        "running and the firewall isn't intercepting the "
                        "connection. Re-run scan from an internal vantage. "
                        "If FTP is intentionally filtered at the perimeter, "
                        "that is good hardening - FTP is plaintext and should "
                        "be replaced with SFTP."),
        "cwe": "CWE-1006",
    }


def _findings_by_severity(s):
    """Return methodology_findings grouped by severity (computed from
    confidence + privilege_level)."""
    out = {"CRITICAL": [], "MEDIUM": [], "LOW": []}
    for f in (s.get("methodology_findings") or []):
        conf = f.get("confidence", "SUSPECTED")
        priv = f.get("privilege_level", "unknown")
        if conf == "CONFIRMED":
            if priv == "admin": out["CRITICAL"].append(f)
            elif priv == "user": out["MEDIUM"].append(f)
            else: out["LOW"].append(f)
        else:
            out["LOW"].append(f)
    return out


def rule_confirmed_admin(s):
    g = _findings_by_severity(s)
    if not g["CRITICAL"]:
        return None
    return {
        "name": f"CONFIRMED admin FTP access via password ({len(g['CRITICAL'])} account)",
        "severity": "CRITICAL", "cvss": "9.8",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": ("File-write-capable FTP account(s) compromised via password "
                     "spray. Verified by separate ftplib login + STOR test file "
                     "(verification_method=ftplib_second_login_list). Attacker "
                     "can upload arbitrary files, including web shells if the "
                     "ftp root overlaps the webroot. Compromised users: " +
                     ", ".join(f["user"] for f in g["CRITICAL"][:5])),
        "remediation": ("CRITICAL - rotate the affected FTP passwords immediately. "
                        "Migrate from FTP to SFTP (OpenSSH) - FTP transmits "
                        "credentials and file contents in plaintext. Enforce "
                        "strong password policy + lock accounts after N failed "
                        "logins (vsftpd: 'max_login_fails=3'). Audit "
                        "/var/log/vsftpd.log for prior unauthorized uploads. "
                        "Treat the FTP root as compromised until proven clean - "
                        "check for uploaded web shells."),
    }


def rule_confirmed_user(s):
    g = _findings_by_severity(s)
    if not g["MEDIUM"]:
        return None
    return {
        "name": f"CONFIRMED user-level FTP access via password ({len(g['MEDIUM'])} account)",
        "severity": "MEDIUM", "cvss": "6.5",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": ("Regular FTP account(s) compromised with read access "
                     "(verified via /etc/passwd RETR). No write capability "
                     "observed but attacker can exfiltrate any world-readable "
                     "file. Compromised users: " +
                     ", ".join(f["user"] for f in g["MEDIUM"][:5])),
        "remediation": ("Force password reset on the affected accounts. Notify "
                        "account owner(s). Migrate from FTP to SFTP (plaintext "
                        "creds on the wire). Consider chroot'ing FTP users to "
                        "their home directory to limit read scope."),
    }


def rule_confirmed_guest(s):
    g = _findings_by_severity(s)
    confirmed_guest = [f for f in g["LOW"]
                       if f.get("confidence") == "CONFIRMED"
                       and f.get("privilege_level") == "guest"]
    if not confirmed_guest:
        return None
    return {
        "name": f"CONFIRMED guest FTP access ({len(confirmed_guest)} account)",
        "severity": "LOW", "cvss": "4.3",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": ("Guest/anonymous-equivalent FTP login succeeded but no "
                     "read of /etc/passwd or write of test file was observed. "
                     "Account is functionally a public dropbox. Users: " +
                     ", ".join(f["user"] for f in confirmed_guest[:5])),
        "remediation": ("Confirm this account is intentionally public-facing. "
                        "If not, disable it. If yes, ensure it is chroot'd "
                        "to a read-only directory containing only intended "
                        "public files."),
    }


def rule_suspected(s):
    g = _findings_by_severity(s)
    suspected = [f for f in g["LOW"] if f.get("confidence") == "SUSPECTED"]
    if not suspected:
        return None
    return {
        "name": f"SUSPECTED FTP credential ({len(suspected)} - needs manual verification)",
        "severity": "LOW", "cvss": "3.7",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": ("ftplib login() returned success but the verification "
                     "session could not run LIST (auth OK, listing failed). "
                     "Could be a chroot misconfiguration OR a login-only "
                     "account with no directory access. Users: " +
                     ", ".join(f["user"] for f in suspected[:5])),
        "remediation": ("Manually verify with an FTP client. If file ops DO "
                        "work, treat as MEDIUM/CRITICAL per privilege. If "
                        "auth-only with no shell, harden by removing the "
                        "account's password entirely - if no file ops are "
                        "intended, no login should be possible."),
    }


def rule_chain_handoff(s):
    chain_next = s.get("chain_next") or []
    if not chain_next:
        return None
    return {
        "name": "Cross-scanner chain handoff suggested",
        "severity": "INFO",
        "evidence": ("Confirmed credentials enable downstream scanners: " +
                     ", ".join(chain_next)),
        "remediation": ("Re-run scan with chain_id propagation to automatically "
                        "follow up with: " + ", ".join(chain_next) + ". "
                        "These will inherit the captured credentials via the "
                        "VL-METHOD chaining engine."),
        "cwe": "CWE-1006",
    }


FTP_BRUTE_FINDING_RULES = [
    rule_unreachable,
    rule_input_missing,
    rule_anonymous_enabled,
    rule_positive_quick,
    rule_inconclusive,
    rule_confirmed_admin,
    rule_confirmed_user,
    rule_confirmed_guest,
    rule_suspected,
    rule_chain_handoff,
]
