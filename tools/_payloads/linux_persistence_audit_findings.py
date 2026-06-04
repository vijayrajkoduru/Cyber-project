"""linux_persistence_audit - findings rules.

Severity model:
  HIGH      malicious patterns (reverse shell / curl|sh / base64 exec /
            /tmp executable in persistence config)
  MEDIUM    unexpected entry on a persistence surface (not baseline-clean)
  INFO      SSH creds missing / paramiko missing / connection failed
  POSITIVE  audit ran and every line matched baseline (no unknown entries)
"""


def rule_high_persistence(s):
    hits = s.get("linux_persistence_high_hits") or []
    if not hits:
        return None
    categories = sorted({h.get("category") for h in hits if h.get("category")})
    patterns = sorted({h.get("pattern") for h in hits if h.get("pattern")})
    sample = "; ".join(
        f"{h.get('category')}: {h.get('file', '?')}: {h.get('line', '')[:80]}"
        for h in hits[:3]
    )
    return {
        "name": (f"Live attacker persistence detected on Linux host "
                 f"({len(hits)} suspicious entries in {', '.join(categories)})"),
        "severity": "HIGH",
        "cvss": "8.8",
        "cwe": "CWE-506",
        "owasp": "A05:2021",
        "mitre": "T1053.003, T1543.002, T1546.004",
        "evidence": (
            f"Patterns matched: {', '.join(patterns)}. "
            f"Examples: {sample}"
        ),
        "remediation": (
            "1. Isolate the host from the network NOW and snapshot disk + "
            "memory for forensics. 2. Audit /etc/passwd and ~/.ssh/ for "
            "rogue users/keys (likely co-installed). 3. Compare every flagged "
            "file against the package-shipped version (`dpkg -S` / `rpm -Vf`). "
            "4. Rebuild from a known-clean image rather than cleaning in place "
            "- attacker may have planted multiple persistence layers. "
            "5. Rotate all credentials reachable from this host."
        ),
    }


def rule_medium_unknown(s):
    hits = s.get("linux_persistence_medium_hits") or []
    if not hits:
        return None
    categories = sorted({h.get("category") for h in hits if h.get("category")})
    files_seen = sorted({h.get("file") for h in hits if h.get("file")})[:10]
    return {
        "name": (f"Unexpected entries on Linux persistence surface "
                 f"({len(hits)} lines in {', '.join(categories)})"),
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-506",
        "owasp": "A05:2021",
        "mitre": "T1053.003, T1037.004, T1546.004",
        "evidence": (
            f"Files containing non-baseline lines: {', '.join(files_seen)}. "
            f"Total non-baseline lines: {len(hits)} (sampled). "
            "These don't match a known-clean Debian/Ubuntu baseline but also "
            "don't match a confirmed-malicious pattern - they may be "
            "legitimate ops scripts or attacker drop-ins."
        ),
        "remediation": (
            "1. For each flagged file, confirm with the system owner whether "
            "the entry is legitimate (config-management drop-in, vendor "
            "agent, etc.). 2. If unknown, treat as suspect and rotate any "
            "creds reachable from the line's exec context. 3. Move legitimate "
            "ops scripts into a labelled subdir (/etc/cron.d/ops-*) so future "
            "scans can baseline them. 4. Pin /etc/cron.d/ via auditd file "
            "watches so new entries trigger alerts."
        ),
    }


def rule_creds_missing(s):
    if not s.get("linux_persistence_creds_missing"):
        return None
    return {
        "name": "Linux persistence audit skipped - SSH credentials not supplied",
        "severity": "INFO",
        "evidence": ("This probe requires options.username + options.password "
                     "(or options.ssh_key) to SSH into the target. Without "
                     "creds no audit ran."),
        "remediation": (
            "Re-run with options.username + options.password (or "
            "options.ssh_key, PEM-format). Recommended: create a read-only "
            "audit account (`useradd -r -s /bin/bash vl-audit` + restricted "
            "sudoers entry) and pin the key in your VulnusLab credentials "
            "vault."
        ),
        "cwe": "CWE-1006",
    }


def rule_auth_failed(s):
    if not s.get("linux_persistence_ssh_auth_failed"):
        return None
    return {
        "name": "SSH authentication failed during persistence audit",
        "severity": "INFO",
        "evidence": ("paramiko returned AuthenticationException with the "
                     "supplied username/password (or key). No audit data "
                     "was collected."),
        "remediation": (
            "Verify the credential is valid on the target. If using a key, "
            "confirm the public counterpart is in ~/.ssh/authorized_keys and "
            "that PubkeyAuthentication is enabled. Check /var/log/auth.log "
            "on the target for the rejection reason."
        ),
        "cwe": "CWE-287",
    }


def rule_paramiko_missing(s):
    if "paramiko not installed" not in str(s.get("linux_persistence_audit_error") or ""):
        return None
    return {
        "name": "paramiko library not installed on scanner host",
        "severity": "INFO",
        "evidence": "import paramiko failed. Probe could not execute.",
        "remediation": "pip install paramiko (already part of Kali base image).",
        "cwe": "CWE-1006",
    }


def rule_connect_error(s):
    err = str(s.get("linux_persistence_audit_error") or "")
    if not err or "paramiko" in err or "timeout" not in err and "ssh" not in err:
        return None
    return {
        "name": "SSH connection failed during persistence audit",
        "severity": "INFO",
        "evidence": f"paramiko reported: {err}",
        "remediation": ("Verify the target SSH service is reachable, port is "
                        "open, and firewall allows the scanner IP. Re-run "
                        "once connectivity is confirmed."),
        "cwe": "CWE-1006",
    }


def rule_positive(s):
    if s.get("linux_persistence_audit_total"):
        return None
    if s.get("linux_persistence_creds_missing"):
        return None
    if s.get("linux_persistence_ssh_auth_failed"):
        return None
    if s.get("linux_persistence_audit_error"):
        return None
    if not s.get("linux_persistence_lines_scanned"):
        return None
    return {
        "name": "Linux persistence surface clean (no suspicious entries)",
        "severity": "POSITIVE",
        "evidence": (
            f"{s.get('linux_persistence_lines_scanned', 0)} lines across cron / "
            "systemd / init.d / shell-rc audited. All entries matched a "
            "known-clean Debian/Ubuntu baseline; no live reverse-shell / "
            "curl|sh / base64-exec patterns detected."
        ),
        "remediation": (
            "Continue running this audit on a weekly cadence and integrate "
            "auditd file-watches on /etc/cron.* and /etc/systemd/system/ for "
            "real-time change alerts."
        ),
        "cwe": "CWE-506",
        "owasp": "A05:2021",
    }


LINUX_PERSISTENCE_AUDIT_FINDING_RULES = [
    rule_high_persistence,
    rule_medium_unknown,
    rule_creds_missing,
    rule_auth_failed,
    rule_paramiko_missing,
    rule_connect_error,
    rule_positive,
]
