"""sudo_misconfig_audit - findings rules.

Severity model:
  CRITICAL - NOPASSWD entry with GTFOBins-exploitable binary (instant root)
           - LD_PRELOAD / LD_LIBRARY_PATH in env_keep (shared-lib privesc)
           - sudo -l works passwordless and shows ALL commands
  HIGH     - NOPASSWD on non-GTFOBins binary (still skips password challenge)
           - Wildcards in command path (cp/tar/find with *)
  INFO     - credentials missing / SSH unreachable
  POSITIVE - sudo policy requires password + no env_keep + no wildcards
"""


def rule_critical_gtfobins_nopasswd(s):
    hits = s.get("sudo_gtfobins_nopasswd") or []
    if not hits:
        return None
    sample = ", ".join(sorted({h.get("binary", "?") for h in hits}))[:200]
    return {
        "name": f"sudo NOPASSWD on GTFOBins binary — instant root x{len(hits)}",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-269",
        "owasp": "A01:2021",
        "evidence": (f"sudoers grants NOPASSWD on: {sample}. Each of these is in "
                     "GTFOBins — any user listed in the sudoers rule reaches root "
                     "without a password (e.g. `sudo find / -exec /bin/sh \\;`)."),
        "remediation": (
            "1. Remove NOPASSWD from each rule that grants a GTFOBins binary "
            "(/etc/sudoers + /etc/sudoers.d/*). 2. If passwordless execution is "
            "operationally required, restrict to a non-shell-escape wrapper "
            "(e.g. /usr/local/bin/safe-restart-app) and audit the wrapper. "
            "3. Visudo any change (visudo -c verifies syntax). "
            "4. Audit `getent group sudo` + wheel to confirm only intended users."
        ),
    }


def rule_critical_env_keep_preload(s):
    if not s.get("sudo_env_keep_preload"):
        return None
    return {
        "name": "sudoers env_keep includes LD_PRELOAD / LD_LIBRARY_PATH",
        "severity": "CRITICAL",
        "cvss": "9.1",
        "cwe": "CWE-426",
        "owasp": "A01:2021",
        "evidence": ("sudoers Defaults env_keep+= retains LD_PRELOAD or LD_LIBRARY_PATH. "
                     "Any sudoer can drop a shared library that runs as root when sudo "
                     "invokes any command (classic LD_PRELOAD privesc)."),
        "remediation": (
            "Remove LD_PRELOAD/LD_LIBRARY_PATH from `Defaults env_keep` in /etc/sudoers. "
            "Set `Defaults env_reset` (default in modern sudo) to wipe inherited env. "
            "Run sudo --version — if older than 1.9.5p2 also patch Baron Samedit (CVE-2021-3156)."
        ),
    }


def rule_critical_all_passwordless(s):
    if not s.get("sudo_all_nopasswd"):
        return None
    return {
        "name": "sudo NOPASSWD: ALL — passwordless full root",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-269",
        "owasp": "A01:2021",
        "evidence": ("sudoers grants `(ALL) NOPASSWD: ALL` to one or more users/groups. "
                     "Anyone in that group reaches root with `sudo -i`."),
        "remediation": (
            "Replace `NOPASSWD: ALL` with a narrowly scoped command list, OR require "
            "a password (`%admin ALL=(ALL) ALL`). For automation accounts, use "
            "a dedicated wrapper script + auditd logging instead of NOPASSWD: ALL."
        ),
    }


def rule_high_nopasswd(s):
    hits = s.get("sudo_nopasswd_other") or []
    if not hits:
        return None
    sample = ", ".join(sorted({h.get("binary", "?") for h in hits}))[:200]
    return {
        "name": f"sudo NOPASSWD entries — {len(hits)} (non-GTFOBins)",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-269",
        "evidence": (f"sudoers NOPASSWD on: {sample}. Even if not directly GTFOBins, "
                     "passwordless privileged exec lets a stolen shell escalate without "
                     "triggering the password prompt that an attacker can't satisfy."),
        "remediation": (
            "Require password for sudo unless strictly justified. If kept, document "
            "the rationale in the rule comment, and ensure the binary has no shell "
            "escape (`!` in less, `:!sh` in vi, etc.)."
        ),
    }


def rule_high_wildcards(s):
    hits = s.get("sudo_wildcards") or []
    if not hits:
        return None
    sample = ", ".join(hits[:5])[:200]
    return {
        "name": f"sudoers command wildcards — {len(hits)} risky pattern(s)",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-78",
        "evidence": (f"Wildcard patterns in sudoers commands: {sample}. Wildcards in "
                     "paths/args enable argument injection (e.g. `sudo /usr/bin/find /tmp/* "
                     "-name X` -> pass `-exec /bin/sh \\;`)."),
        "remediation": (
            "Replace wildcards with explicit paths and arguments. If multiple files "
            "must be accepted, write a sanitizing wrapper script that validates input "
            "before invoking the underlying command."
        ),
    }


def rule_no_creds(s):
    if not s.get("sudo_no_creds"):
        return None
    return {
        "name": "Sudo misconfig audit skipped - SSH credentials required",
        "severity": "INFO",
        "evidence": ("This scanner needs SSH access. Supply options.username + "
                     "options.password OR options.ssh_key on the request."),
        "remediation": "Re-run with options.username + options.password (or options.ssh_key).",
        "cwe": "CWE-1006",
    }


def rule_ssh_failed(s):
    err = s.get("sudo_ssh_error")
    if not err:
        return None
    return {
        "name": "Sudo misconfig audit failed - SSH connection error",
        "severity": "INFO",
        "evidence": f"SSH error: {str(err)[:200]}",
        "remediation": "Verify SSH port + creds; check options.port if non-22.",
        "cwe": "CWE-1006",
    }


def rule_positive(s):
    if s.get("sudo_no_creds") or s.get("sudo_ssh_error"):
        return None
    if not s.get("sudo_audit_ran"):
        return None
    if (s.get("sudo_gtfobins_nopasswd") or s.get("sudo_env_keep_preload") or
        s.get("sudo_all_nopasswd") or s.get("sudo_nopasswd_other") or
        s.get("sudo_wildcards")):
        return None
    return {
        "name": "sudo policy clean - password required, no dangerous patterns",
        "severity": "POSITIVE",
        "evidence": ("Reviewed /etc/sudoers + /etc/sudoers.d/* + `sudo -l`: no NOPASSWD, "
                     "no env_keep on LD_PRELOAD/LD_LIBRARY_PATH, no wildcards in "
                     "command paths, and no GTFOBins binaries directly granted."),
        "remediation": ("Re-audit sudoers quarterly and after every IT admin change. "
                        "Keep sudo up to date for CVE-2021-3156 (Baron Samedit) class fixes."),
        "cwe": "CWE-269",
        "owasp": "A01:2021",
    }


SUDO_MISCONFIG_AUDIT_FINDING_RULES = [
    rule_critical_gtfobins_nopasswd,
    rule_critical_env_keep_preload,
    rule_critical_all_passwordless,
    rule_high_nopasswd,
    rule_high_wildcards,
    rule_no_creds,
    rule_ssh_failed,
    rule_positive,
]
