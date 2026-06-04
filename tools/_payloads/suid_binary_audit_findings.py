"""suid_binary_audit - findings rules.

Severity model:
  CRITICAL - SUID binary present that is listed in GTFOBins (instant root path)
  HIGH     - SUID binary present that is unusual (not in common-allow list)
  INFO     - credentials missing / SSH unreachable / no GTFOBins DB
  POSITIVE - only the well-known safe SUIDs found (su, sudo, mount, etc.)
"""

# Distro-default safe SUIDs (still privileged but expected on every box).
SAFE_SUID_BASENAMES = {
    "su", "sudo", "mount", "umount", "newgrp", "gpasswd", "passwd",
    "chage", "chsh", "chfn", "pkexec", "ping", "ping6", "fusermount",
    "fusermount3", "ntfs-3g", "unix_chkpwd", "ssh-agent", "ssh-keysign",
    "vmware-user-suid-wrapper", "polkit-agent-helper-1",
    "dbus-daemon-launch-helper",
}


def rule_critical_gtfobins(s):
    hits = s.get("suid_gtfobins_hits") or []
    if not hits:
        return None
    sample = ", ".join(sorted({h.get("binary", "?") for h in hits}))[:300]
    return {
        "name": f"GTFOBins-exploitable SUID binaries present — {len(hits)} root path(s)",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-250",
        "owasp": "A01:2021",
        "evidence": (f"Found SUID-root binaries listed in GTFOBins: {sample}. "
                     "Any local user can chain these to instant root (e.g. "
                     "`find . -exec /bin/sh \\;` if find is SUID)."),
        "remediation": (
            "1. Remove SUID bit immediately on each flagged binary: "
            "chmod u-s /path/to/binary  (e.g. chmod u-s /usr/bin/find). "
            "2. If the binary legitimately needs to run privileged for one task, "
            "wrap it in sudoers with a tight command spec instead of SUID. "
            "3. Audit /etc/passwd shells + /etc/sudoers for the user(s) who could "
            "have reached this SUID; rotate any local passwords. "
            "4. Enable auditd rule `-a always,exit -F arch=b64 -S execve -F path="
            "/usr/bin/SUID -k suid-exec` to catch future abuse."
        ),
    }


def rule_high_unusual(s):
    unusual = s.get("suid_unusual") or []
    if not unusual:
        return None
    sample = ", ".join(unusual[:8])
    return {
        "name": f"Unusual SUID-root binaries detected — {len(unusual)} non-default",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-250",
        "evidence": (f"SUID-root binaries not on the distro-default allow-list: {sample}. "
                     "These may be vendor add-ons, custom scripts, or attacker plants."),
        "remediation": (
            "Review each non-default SUID: confirm vendor source, check for known CVEs, "
            "and remove the SUID bit if elevated execution isn't strictly required "
            "(chmod u-s /path/to/bin). If retained, monitor file integrity with AIDE/Tripwire."
        ),
    }


def rule_no_creds(s):
    if not s.get("suid_no_creds"):
        return None
    return {
        "name": "SUID binary audit skipped - SSH credentials required",
        "severity": "INFO",
        "evidence": ("This scanner needs SSH access. Supply options.username + "
                     "options.password OR options.ssh_key on the request."),
        "remediation": "Re-run with options.username + options.password (or options.ssh_key).",
        "cwe": "CWE-1006",
    }


def rule_ssh_failed(s):
    err = s.get("suid_ssh_error")
    if not err:
        return None
    return {
        "name": "SUID binary audit failed - SSH connection error",
        "severity": "INFO",
        "evidence": f"SSH error: {str(err)[:200]}",
        "remediation": "Verify SSH port + creds; check options.port if non-22.",
        "cwe": "CWE-1006",
    }


def rule_gtfobins_missing(s):
    if not s.get("suid_gtfobins_db_missing"):
        return None
    return {
        "name": "GTFOBins database missing - cross-reference unavailable",
        "severity": "INFO",
        "evidence": "/opt/gtfobins/_gtfobins/ not found; SUID list reported "
                    "without per-binary exploit lookup.",
        "remediation": ("Clone GTFOBins on backend host: git clone "
                        "https://github.com/GTFOBins/GTFOBins.github.io /opt/gtfobins"),
        "cwe": "CWE-1006",
    }


def rule_positive(s):
    if not s.get("suid_total_found") or s.get("suid_no_creds") or s.get("suid_ssh_error"):
        return None
    if s.get("suid_gtfobins_hits") or s.get("suid_unusual"):
        return None
    return {
        "name": "SUID inventory clean - only distro-default SUIDs present",
        "severity": "POSITIVE",
        "evidence": (f"Found {s.get('suid_total_found', 0)} SUID-root binaries — "
                     "all match the distro-default safe list "
                     "(su/sudo/mount/passwd/pkexec/etc)."),
        "remediation": ("Maintain this baseline. Re-run quarterly and after any "
                        "package install or major upgrade."),
        "cwe": "CWE-250",
    }


SUID_BINARY_AUDIT_FINDING_RULES = [
    rule_critical_gtfobins,
    rule_high_unusual,
    rule_no_creds,
    rule_ssh_failed,
    rule_gtfobins_missing,
    rule_positive,
]
