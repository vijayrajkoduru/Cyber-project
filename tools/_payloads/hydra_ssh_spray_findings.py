"""hydra_ssh_spray - finding rules (VL-METHOD aware).

REWRITTEN 2026-06-05 for the VL-METHOD methodology pattern. Reads new
state keys populated by HydraSshSpray's 7-stage flow:
  - methodology_findings  : list of verified credentials
  - port_reachable        : bool from pre_flight
  - fingerprint           : dict {service, version, comments}
  - chain_next            : list of follow-up scanner names

Severity now derives from CONFIRMED+privilege_level combination:
  CONFIRMED root      -> CRITICAL  CVSS 9.8
  CONFIRMED sudo      -> HIGH      CVSS 8.1
  CONFIRMED user      -> MEDIUM    CVSS 6.5
  CONFIRMED guest     -> LOW       CVSS 4.3
  SUSPECTED any       -> LOW       CVSS 3.7  (flagged for manual confirm)
"""


def rule_unreachable(s):
    if s.get("port_reachable") is not False:
        return None
    return {
        "name": "SSH port unreachable - cannot test password security",
        "severity": "INFO",
        "evidence": s.get("skipped_reason") or "Port 22 closed or filtered",
        "remediation": ("If SSH is meant to be exposed, verify firewall + sshd is "
                        "running. If SSH is intentionally blocked, this is good. "
                        "Re-run scan once SSH is reachable to actually test "
                        "credential strength."),
        "cwe": "CWE-1006",
    }


def rule_input_missing(s):
    # Only fires when pre_flight succeeded but customer didn't provide
    # userlist/passlist for the deep_scan stage. Quick-probe still ran
    # against 5 known defaults regardless of customer input.
    deep_skipped = s.get("deep_skipped") or ""
    if "userlist/passlist not supplied" not in deep_skipped:
        return None
    hits = s.get("methodology_total", 0)
    if hits > 0:
        # If quick-probe already found something, don't dilute with INFO
        return None
    return {
        "name": "Deep spray skipped - userlist/passlist not provided",
        "severity": "INFO",
        "evidence": ("Quick-probe ran 5 known-bad defaults (root/root, admin/admin, "
                     "pi/raspberry, ubuntu/ubuntu, test/test) - none worked. To run "
                     "a full spray, provide options.userlist + options.passlist on "
                     "the request body (newline-separated). Max 10 users x 25 pwds."),
        "remediation": ("Supply options.userlist + options.passlist to test against "
                        "your organization's password policy (or a known-leaked "
                        "wordlist like rockyou-top-100)."),
        "cwe": "CWE-1006",
    }


def _ssh_responded(s) -> bool:
    """True if SSH banner-grab actually got bytes back from a real sshd.
    SSH servers send the SSH-2.0-XXX banner immediately on TCP connect, so
    an empty banner means filtered-accept firewall or non-SSH service."""
    fp = s.get("fingerprint") or {}
    return bool(fp.get("raw") or fp.get("version") or fp.get("service") == "ssh")


def rule_positive_quick(s):
    # Quick-probe ran, no hits, no real findings - GOOD signal.
    # Guard: only fire POSITIVE if SSH banner-grab actually saw a real
    # sshd. See rule_inconclusive for filtered-accept / no-banner case.
    if s.get("methodology_total", 0) > 0:
        return None
    if s.get("port_reachable") is not True:
        return None
    if s.get("quick_probe_attempts", 0) == 0:
        return None
    if not _ssh_responded(s):
        return None  # no banner -> rule_inconclusive
    return {
        "name": "SSH rejects all 5 known-bad default credentials",
        "severity": "POSITIVE",
        "evidence": (f"Tried {s.get('quick_probe_attempts', 5)} known-bad defaults "
                     f"(root/root, admin/admin, pi/raspberry, ubuntu/ubuntu, test/test); "
                     f"all rejected. SSH banner: {(s.get('fingerprint') or {}).get('version', 'unknown')}"),
        "remediation": "Continue blocking default credentials. Consider key-only auth (PasswordAuthentication no in sshd_config) for production hosts.",
        "cwe": "CWE-521",
        "owasp": "A07:2021",
    }


def rule_inconclusive(s):
    """Port accepts TCP SYN but no SSH banner emerged - filtered-accept
    firewall or non-SSH service on port 22. Emit INFO so PDF doesn't
    falsely claim "SSH rejects defaults" when we never spoke SSH."""
    if s.get("methodology_total", 0) > 0:
        return None
    if s.get("port_reachable") is not True:
        return None
    if s.get("quick_probe_attempts", 0) == 0:
        return None
    if _ssh_responded(s):
        return None
    return {
        "name": "SSH port reachable but no banner returned - credential security UNVERIFIED",
        "severity": "INFO",
        "evidence": (f"TCP/22 accepted the connection but no SSH-2.0 banner was "
                     f"received and {s.get('quick_probe_attempts', 5)} paramiko "
                     "default-credential attempts errored/timed-out. This is "
                     "typical of stateful firewalls that 'accept-and-RST' filtered "
                     "ports or a non-SSH service squatting on port 22. We cannot "
                     "claim credentials are strong - we never reached sshd."),
        "remediation": ("If this host is supposed to expose SSH, verify sshd is "
                        "running and the firewall isn't intercepting the "
                        "connection. Re-run scan from an internal vantage. "
                        "If SSH is intentionally filtered at the perimeter, "
                        "that is good hardening."),
        "cwe": "CWE-1006",
    }


def _findings_by_severity(s):
    """Return methodology_findings grouped by severity (computed from
    confidence + privilege_level)."""
    out = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for f in (s.get("methodology_findings") or []):
        conf = f.get("confidence", "SUSPECTED")
        priv = f.get("privilege_level", "unknown")
        if conf == "CONFIRMED":
            if priv == "root": out["CRITICAL"].append(f)
            elif priv == "sudo": out["HIGH"].append(f)
            elif priv in ("user", "service"): out["MEDIUM"].append(f)
            else: out["LOW"].append(f)
        else:
            out["LOW"].append(f)
    return out


def rule_confirmed_root(s):
    g = _findings_by_severity(s)
    if not g["CRITICAL"]:
        return None
    return {
        "name": f"CONFIRMED root SSH access via password ({len(g['CRITICAL'])} account)",
        "severity": "CRITICAL", "cvss": "9.8",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": ("Root account(s) compromised via password spray. "
                     "Verified by separate paramiko session running `id` command "
                     "(verification_method=paramiko_second_session_id_cmd). "
                     "Compromised users: " +
                     ", ".join(f["user"] for f in g["CRITICAL"][:5])),
        "remediation": ("CRITICAL - rotate root password immediately on affected host(s). "
                        "Set PermitRootLogin=no in /etc/ssh/sshd_config (or "
                        "PermitRootLogin=prohibit-password for cloud images). "
                        "Enforce key-only auth: PasswordAuthentication=no. "
                        "Audit /var/log/auth.log for prior unauthorized logins. "
                        "Consider this host compromised until proven clean."),
    }


def rule_confirmed_sudo(s):
    g = _findings_by_severity(s)
    if not g["HIGH"]:
        return None
    return {
        "name": f"CONFIRMED sudo-capable SSH access via password ({len(g['HIGH'])} account)",
        "severity": "HIGH", "cvss": "8.1",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": ("Sudo-group user(s) compromised. Privilege escalation to root "
                     "is one `sudo` command away. Verified by separate paramiko "
                     "session. Compromised users: " +
                     ", ".join(f["user"] for f in g["HIGH"][:5])),
        "remediation": ("Rotate passwords for the compromised sudo users. Enforce "
                        "strong password policy (libpam-pwquality) + key-only auth. "
                        "Review sudoers file for unnecessarily-broad sudo grants. "
                        "Enable 2FA via google-authenticator-pam for sudo users."),
    }


def rule_confirmed_user(s):
    g = _findings_by_severity(s)
    if not g["MEDIUM"]:
        return None
    return {
        "name": f"CONFIRMED regular user SSH access via password ({len(g['MEDIUM'])} account)",
        "severity": "MEDIUM", "cvss": "6.5",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": ("Regular user account(s) compromised. Local privesc required "
                     "for further impact. Verified by paramiko second session. "
                     "Compromised users: " +
                     ", ".join(f["user"] for f in g["MEDIUM"][:5])),
        "remediation": ("Force password reset on the affected accounts. Notify "
                        "account owner(s). Consider enabling password complexity "
                        "policy + key-only auth for SSH access."),
    }


def rule_suspected(s):
    g = _findings_by_severity(s)
    if not g["LOW"]:
        return None
    suspected = [f for f in g["LOW"] if f.get("confidence") == "SUSPECTED"]
    if not suspected:
        return None
    return {
        "name": f"SUSPECTED SSH credential ({len(suspected)} - needs manual verification)",
        "severity": "LOW", "cvss": "3.7",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": ("Hydra reported these credentials as valid but verification "
                     "session could not confirm shell access. Could be hydra false-"
                     "positive OR account with login-but-no-shell (e.g. /sbin/nologin). "
                     "Users: " + ", ".join(f["user"] for f in suspected[:5])),
        "remediation": ("Manually verify with ssh client. If shell DOES work, treat "
                        "as confirmed MEDIUM/HIGH/CRITICAL per privilege. If shell "
                        "blocked but auth succeeds, harden by setting account's "
                        "shell to /sbin/nologin AND removing password entirely."),
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


HYDRA_SSH_SPRAY_FINDING_RULES = [
    rule_unreachable,
    rule_input_missing,
    rule_positive_quick,
    rule_inconclusive,
    rule_confirmed_root,
    rule_confirmed_sudo,
    rule_confirmed_user,
    rule_suspected,
    rule_chain_handoff,
]
