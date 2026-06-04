"""linpeas_remote_audit - findings rules.

Severity model:
  CRITICAL - writable /etc/shadow, exposed Docker socket, root SUID anomalies
  HIGH     - cleartext creds in env/cron, writable PATH dirs, NFS no_root_squash
  MEDIUM   - misc LinPEAS HIGH lines (kernel old, capabilities, weak crons)
  INFO     - credentials missing / SSH unreachable / linpeas missing
  POSITIVE - LinPEAS ran with 0 HIGH-severity findings (rare)
"""


def _crit_findings(s):
    return [f for f in (s.get("linpeas_findings") or []) if f.get("severity") == "CRITICAL"]


def _high_findings(s):
    return [f for f in (s.get("linpeas_findings") or []) if f.get("severity") == "HIGH"]


def _med_findings(s):
    return [f for f in (s.get("linpeas_findings") or []) if f.get("severity") == "MEDIUM"]


def rule_critical(s):
    crit = _crit_findings(s)
    if not crit:
        return None
    summary = "; ".join(f.get("title", "?")[:80] for f in crit[:5])
    return {
        "name": f"LinPEAS flagged {len(crit)} CRITICAL privilege-escalation vector(s)",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-269",
        "owasp": "A01:2021",
        "evidence": f"LinPEAS -a run on {s.get('linpeas_host', 'target')} returned: {summary}",
        "remediation": (
            "1. Remediate each CRITICAL vector: writable /etc/shadow -> chown root:shadow + 0640; "
            "exposed /var/run/docker.sock -> revoke group docker membership for non-root users; "
            "root SUID anomalies -> remove SUID bit (chmod u-s) on unexpected binaries. "
            "2. Re-run LinPEAS after each fix and confirm CRITICAL count = 0. "
            "3. Enforce CIS Linux Benchmark §6 (Filesystem Permissions) on all production hosts."
        ),
    }


def rule_high(s):
    high = _high_findings(s)
    if not high:
        return None
    summary = "; ".join(f.get("title", "?")[:80] for f in high[:5])
    return {
        "name": f"LinPEAS flagged {len(high)} HIGH-severity privilege-escalation vector(s)",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-269",
        "owasp": "A01:2021",
        "evidence": f"LinPEAS HIGH findings: {summary}",
        "remediation": (
            "Address each HIGH item — cleartext creds in env/cron -> move to a secret store "
            "(HashiCorp Vault / AWS SSM); writable PATH dirs -> tighten directory ownership "
            "(root:root 0755); NFS no_root_squash -> add root_squash to exports. "
            "Re-run LinPEAS after fixes."
        ),
    }


def rule_medium(s):
    med = _med_findings(s)
    if not med:
        return None
    return {
        "name": f"LinPEAS flagged {len(med)} medium-severity hardening gap(s)",
        "severity": "MEDIUM",
        "cwe": "CWE-269",
        "evidence": f"LinPEAS surfaced {len(med)} medium findings (capabilities, weak crons, "
                    f"old kernel, etc.). See raw_data.linpeas_findings for full list.",
        "remediation": (
            "Triage each medium finding. Often the fix is patching the kernel "
            "(apt full-upgrade), removing unneeded capabilities (setcap -r BIN), "
            "or tightening cron job ownership."
        ),
    }


def rule_no_creds(s):
    if not s.get("linpeas_no_creds"):
        return None
    return {
        "name": "LinPEAS remote audit skipped - SSH credentials required",
        "severity": "INFO",
        "evidence": ("This scanner needs SSH access to the target. Supply "
                     "options.username + options.password OR options.ssh_key "
                     "(PEM/OpenSSH private key as a string)."),
        "remediation": (
            "Re-run with options.username + options.password (or options.ssh_key). "
            "Optionally set options.port (default 22) and options.timeout_sec "
            "(default 300 — LinPEAS -a can take 2-5 minutes on busy hosts)."
        ),
        "cwe": "CWE-1006",
    }


def rule_ssh_failed(s):
    err = s.get("linpeas_ssh_error")
    if not err:
        return None
    return {
        "name": "LinPEAS remote audit failed - SSH connection error",
        "severity": "INFO",
        "evidence": f"SSH to target failed: {str(err)[:200]}",
        "remediation": (
            "Verify target SSH port is reachable, credentials are correct, and "
            "the SSH key (if used) is in PEM/OpenSSH format. Check options.port "
            "if the target listens on a non-22 port."
        ),
        "cwe": "CWE-1006",
    }


def rule_linpeas_missing(s):
    if not s.get("linpeas_script_missing"):
        return None
    return {
        "name": "LinPEAS script not found on scanner host",
        "severity": "INFO",
        "evidence": "/opt/peass-ng/linPEAS/linpeas.sh missing on backend container.",
        "remediation": "Re-clone PEASS-ng: git clone https://github.com/peass-ng/PEASS-ng /opt/peass-ng",
        "cwe": "CWE-1006",
    }


def rule_positive(s):
    if not s.get("linpeas_ran"):
        return None
    if (_crit_findings(s) or _high_findings(s) or _med_findings(s)):
        return None
    return {
        "name": "LinPEAS audit clean - no HIGH/CRITICAL privesc vectors detected",
        "severity": "POSITIVE",
        "evidence": (f"LinPEAS -a ran on {s.get('linpeas_host', 'target')} and "
                     f"returned zero HIGH/CRITICAL findings."),
        "remediation": ("Stay current — patch kernel monthly, audit cron jobs quarterly, "
                        "and re-run LinPEAS after any system administrator change."),
        "cwe": "CWE-269",
        "owasp": "A01:2021",
    }


LINPEAS_REMOTE_AUDIT_FINDING_RULES = [
    rule_critical,
    rule_high,
    rule_medium,
    rule_no_creds,
    rule_ssh_failed,
    rule_linpeas_missing,
    rule_positive,
]
