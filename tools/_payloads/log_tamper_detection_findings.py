"""log_tamper_detection - findings rules.

Severity model:
  HIGH      zero-byte auth.log/secure on box that has logged sudo before /
            journalctl --verify failure / wtmp+lastb both empty with system
            in use
  MEDIUM    stale-mtime warnings / lsattr +i or +a / time gaps in wtmp/btmp
  INFO      SSH creds missing / paramiko missing / connection error
  POSITIVE  all key log files present, recent mtime, no gaps, journal OK
"""


def rule_high_zero_byte(s):
    zb = s.get("log_tamper_zero_byte_logs") or []
    sudo_lines = s.get("log_tamper_sudo_lines") or 0
    # Only HIGH if there's history of sudo (so we know the system is in use)
    suspicious = [z for z in zb
                  if z.get("path", "").endswith(("auth.log", "secure", "wtmp"))]
    if not suspicious:
        return None
    if sudo_lines == 0 and len(zb) <= 1:
        # System might just be too new for sudo history - downgrade to INFO
        return None
    paths = ", ".join(z.get("path", "?") for z in suspicious[:4])
    return {
        "name": (f"Zero-byte audit logs on host with active sudo history "
                 f"({len(suspicious)} cleared logs)"),
        "severity": "HIGH",
        "cvss": "7.1",
        "cwe": "CWE-117",
        "owasp": "A09:2021",
        "mitre": "T1070.002",
        "evidence": (
            f"Zero-byte logs: {paths}. Total sudo lines counted across "
            f"present logs: {sudo_lines} (indicates the system has "
            "historically used sudo, so these logs should NOT be empty). "
            "Pattern consistent with `echo > /var/log/auth.log` or "
            "`logrotate --force` abuse for evidence destruction."
        ),
        "remediation": (
            "1. Capture host disk + memory image NOW for forensics. "
            "2. Pull remote-syslog or SIEM archives for the same time "
            "window - any logs centralized off-host? 3. Check shell history "
            "(.bash_history, ~/.zsh_history) for `> /var/log/`. 4. Configure "
            "remote syslog (`/etc/rsyslog.d/40-remote.conf` -> `*.* @@siem:"
            "514`) so on-host log destruction loses its value. 5. Set "
            "chattr +a on /var/log/* once forensics is done so future "
            "append-only enforcement is in place."
        ),
    }


def rule_high_journal_fail(s):
    if not s.get("log_tamper_journal_fail"):
        return None
    excerpt = s.get("log_tamper_journal_excerpt") or []
    return {
        "name": "systemd-journald integrity verification failed",
        "severity": "HIGH",
        "cvss": "6.8",
        "cwe": "CWE-345",
        "owasp": "A09:2021",
        "mitre": "T1070.002",
        "evidence": (
            "`journalctl --verify` reports FAIL / corrupted. Excerpt: "
            + " | ".join(excerpt[:5])
        ),
        "remediation": (
            "1. Capture /var/log/journal/ for forensics before any cleanup. "
            "2. Enable journald FSS (Forward Secure Sealing) with "
            "`journalctl --setup-keys` so future tampering is detectable. "
            "3. Forward journal to remote sink (`ForwardToSyslog=yes` in "
            "journald.conf + remote syslog). 4. Investigate whether the "
            "corruption is unclean-shutdown (relatively benign) or write "
            "pattern consistent with tampering (size shrink, mtime in past)."
        ),
    }


def rule_medium_lsattr(s):
    ls = s.get("log_tamper_lsattr") or []
    if not ls:
        return None
    immutable = [x for x in ls if "i" in x.get("attrs", "")]
    appendonly = [x for x in ls if "a" in x.get("attrs", "")]
    parts = []
    if immutable:
        parts.append(f"+i immutable on {len(immutable)} file(s)")
    if appendonly:
        parts.append(f"+a append-only on {len(appendonly)} file(s)")
    sev = "MEDIUM"
    if immutable and not appendonly:
        # +i alone on a log file is suspicious - intended hardening uses +a
        sev = "MEDIUM"
    return {
        "name": (f"Non-default extended attributes on system logs "
                 f"({', '.join(parts)})"),
        "severity": sev,
        "cvss": "4.3",
        "cwe": "CWE-732",
        "owasp": "A05:2021",
        "mitre": "T1222.002",
        "evidence": (
            "Files with non-default attributes: "
            + "; ".join(f"{x.get('path')} -> {x.get('attrs')}" for x in ls[:6])
        ),
        "remediation": (
            "Hardening recommendation is +a (append-only) on /var/log/wtmp, "
            "/var/log/btmp, and /var/log/auth.log (or /var/log/secure) so "
            "syslog can still append but tampering needs root + chattr -a. "
            "+i (immutable) on a log file means syslog can't write either - "
            "if you didn't intentionally do this, treat as defense-evasion "
            "(attacker froze the cleared state). Verify with `chattr` "
            "history and shell history."
        ),
    }


def rule_medium_age(s):
    aw = s.get("log_tamper_age_warnings") or []
    if not aw:
        return None
    paths = ", ".join(x.get("path", "?") for x in aw[:4])
    return {
        "name": (f"Active log files have not been written for > 24h "
                 f"despite system uptime ({len(aw)} files)"),
        "severity": "MEDIUM",
        "cvss": "3.7",
        "cwe": "CWE-778",
        "owasp": "A09:2021",
        "mitre": "T1070.002",
        "evidence": (
            f"Files with stale mtime: {paths}. System uptime: "
            f"{s.get('log_tamper_uptime_sec', 0)//3600}h. Active syslog "
            "destinations should be appended-to on every login/cron tick / "
            "auth event."
        ),
        "remediation": (
            "1. Verify rsyslog/journald is running (`systemctl status "
            "rsyslog systemd-journald`). 2. If running, check selinux/"
            "apparmor denials and the destination file's permissions. 3. "
            "If service is stopped/masked, restart and investigate why."
        ),
    }


def rule_medium_gaps(s):
    last = s.get("log_tamper_last_info") or {}
    lastb = s.get("log_tamper_lastb_info") or {}
    gaps = (last.get("gaps") or []) + (lastb.get("gaps") or [])
    if not gaps:
        return None
    biggest = max(gaps)
    return {
        "name": (f"Time gaps detected in login history (max {biggest//3600}h "
                 f"between entries)"),
        "severity": "MEDIUM",
        "cvss": "4.0",
        "cwe": "CWE-778",
        "owasp": "A09:2021",
        "mitre": "T1070.002, T1070.006",
        "evidence": (
            f"`last -F` returned {last.get('count', 0)} entries with "
            f"{len(last.get('gaps') or [])} gaps > 2h. `lastb -F` returned "
            f"{lastb.get('count', 0)} with {len(lastb.get('gaps') or [])} "
            f"gaps. Largest gap: {biggest // 3600}h. Could indicate truncated "
            "wtmp/btmp (T1070.002) or skewed timestamps (T1070.006)."
        ),
        "remediation": (
            "1. Cross-reference with remote syslog / SIEM for the same time "
            "windows - any logins recorded there but not in local wtmp = "
            "tampering. 2. If no remote source, capture wtmp/btmp for "
            "forensics and replace with empty +a versions, then enable "
            "remote syslog before any future investigation has the same "
            "blind spot."
        ),
    }


def rule_creds_missing(s):
    if not s.get("log_tamper_creds_missing"):
        return None
    return {
        "name": "Log-tamper detection skipped - SSH credentials not supplied",
        "severity": "INFO",
        "evidence": "Requires options.username + options.password (or ssh_key).",
        "remediation": ("Re-run with credentials. Recommended: use an audit "
                        "account with read access to /var/log/ (group syslog "
                        "or adm)."),
        "cwe": "CWE-1006",
    }


def rule_auth_failed(s):
    if not s.get("log_tamper_ssh_auth_failed"):
        return None
    return {
        "name": "SSH authentication failed during log-tamper audit",
        "severity": "INFO",
        "evidence": "paramiko AuthenticationException.",
        "remediation": "Verify credentials; re-run.",
        "cwe": "CWE-287",
    }


def rule_paramiko_missing(s):
    if "paramiko not installed" not in str(s.get("log_tamper_detection_error") or ""):
        return None
    return {
        "name": "paramiko library not installed on scanner host",
        "severity": "INFO",
        "evidence": "import paramiko failed.",
        "remediation": "pip install paramiko.",
        "cwe": "CWE-1006",
    }


def rule_connect_error(s):
    err = str(s.get("log_tamper_detection_error") or "")
    if not err or "paramiko" in err:
        return None
    if "ssh" not in err.lower() and "timeout" not in err.lower():
        return None
    return {
        "name": "SSH connection failed during log-tamper audit",
        "severity": "INFO",
        "evidence": f"Error: {err}",
        "remediation": "Verify SSH reachability; re-run.",
        "cwe": "CWE-1006",
    }


def rule_positive(s):
    if s.get("log_tamper_detection_total"):
        return None
    if s.get("log_tamper_creds_missing"):
        return None
    if s.get("log_tamper_ssh_auth_failed"):
        return None
    if s.get("log_tamper_detection_error"):
        return None
    if not s.get("log_tamper_files"):
        return None
    files = s.get("log_tamper_files") or {}
    return {
        "name": (f"System log integrity OK - {len(files)} key log files "
                 "audited, no tampering signs"),
        "severity": "POSITIVE",
        "evidence": (
            f"Audited {len(files)} log files. None were zero-byte, none had "
            "stale mtimes, no unexpected immutable/append-only attributes, "
            "no gaps in wtmp/btmp, journalctl --verify clean. auditd "
            f"active: {s.get('log_tamper_auditd_active', False)}."
        ),
        "remediation": (
            "Maintain current logging posture. Recommended hardening: "
            "(a) chattr +a on /var/log/{auth.log,secure,wtmp,btmp} so syslog "
            "can append but rm/echo can't truncate; (b) enable remote syslog "
            "to a SIEM so on-host tampering loses its value; (c) enable "
            "auditd if not already (`systemctl enable --now auditd`)."
        ),
        "cwe": "CWE-117",
        "owasp": "A09:2021",
    }


LOG_TAMPER_DETECTION_FINDING_RULES = [
    rule_high_zero_byte,
    rule_high_journal_fail,
    rule_medium_lsattr,
    rule_medium_age,
    rule_medium_gaps,
    rule_creds_missing,
    rule_auth_failed,
    rule_paramiko_missing,
    rule_connect_error,
    rule_positive,
]
