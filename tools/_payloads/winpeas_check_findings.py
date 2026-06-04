"""winpeas_check - findings rules.

Severity model:
  CRITICAL - AlwaysInstallElevated registry flag set, stored creds in registry,
             writable service path (binary or quoted path bypass)
  HIGH     - weak service permissions (NT AUTHORITY\\Authenticated Users : Full),
             unquoted service path, world-writable autorun key
  MEDIUM   - misc WinPEAS HIGH lines (legacy SMBv1, weak password policy, etc.)
  INFO     - credentials missing / WinRM unreachable / winpeas binary missing
  POSITIVE - WinPEAS ran with 0 HIGH/CRITICAL items
"""


def _hits(s, sev):
    return [f for f in (s.get("winpeas_findings") or []) if f.get("severity") == sev]


def rule_critical(s):
    crit = _hits(s, "CRITICAL")
    if not crit:
        return None
    summary = "; ".join(f.get("title", "?")[:80] for f in crit[:5])
    return {
        "name": f"WinPEAS flagged {len(crit)} CRITICAL privilege-escalation vector(s)",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-269",
        "owasp": "A01:2021",
        "evidence": (f"WinPEAS run on {s.get('winpeas_host', 'target')} returned: {summary}"),
        "remediation": (
            "1. AlwaysInstallElevated -> set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\"
            "Installer\\AlwaysInstallElevated to 0 AND HKCU\\..\\AlwaysInstallElevated to 0. "
            "2. Stored creds in registry -> remove cmdkey entries (`cmdkey /delete:TARGET`) "
            "and Vault entries; rotate the underlying account passwords. "
            "3. Writable service path -> tighten ACLs (`icacls C:\\Path\\service.exe /remove "
            "Users` then restart service); audit Authenticated Users / Everyone grants. "
            "4. Re-run WinPEAS after each fix to confirm CRITICAL count = 0."
        ),
    }


def rule_high(s):
    high = _hits(s, "HIGH")
    if not high:
        return None
    summary = "; ".join(f.get("title", "?")[:80] for f in high[:5])
    return {
        "name": f"WinPEAS flagged {len(high)} HIGH-severity privilege-escalation vector(s)",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-269",
        "owasp": "A01:2021",
        "evidence": f"WinPEAS HIGH findings: {summary}",
        "remediation": (
            "Address each HIGH item — weak service ACLs -> `icacls /grant` only required principals; "
            "unquoted service path -> `sc config SVC binpath= \"\\\"C:\\Path With Spaces\\svc.exe\\\"\"`; "
            "world-writable autorun key -> regedit ACLs to remove Authenticated Users write."
        ),
    }


def rule_medium(s):
    med = _hits(s, "MEDIUM")
    if not med:
        return None
    return {
        "name": f"WinPEAS flagged {len(med)} medium-severity hardening gap(s)",
        "severity": "MEDIUM",
        "cwe": "CWE-269",
        "evidence": f"WinPEAS surfaced {len(med)} medium findings (legacy SMBv1, weak "
                    "policy, stale users, etc.). See raw_data.winpeas_findings for full list.",
        "remediation": ("Triage each medium item. Common fixes: disable SMBv1 (`Disable-"
                        "WindowsOptionalFeature -Online -FeatureName SMB1Protocol`), tighten "
                        "password policy via secpol.msc, prune stale local users."),
    }


def rule_no_creds(s):
    if not s.get("winpeas_no_creds"):
        return None
    return {
        "name": "WinPEAS check skipped - WinRM credentials required",
        "severity": "INFO",
        "evidence": ("This scanner needs WinRM access. Supply options.username + "
                     "options.password (+ optional options.winrm_port / options.use_ssl)."),
        "remediation": (
            "Re-run with options.username + options.password. Default WinRM port: 5985 "
            "(HTTP) or 5986 (HTTPS). Enable on target: "
            "`Enable-PSRemoting -Force` (run elevated)."
        ),
        "cwe": "CWE-1006",
    }


def rule_winrm_failed(s):
    err = s.get("winpeas_winrm_error")
    if not err:
        return None
    return {
        "name": "WinPEAS check failed - WinRM connection error",
        "severity": "INFO",
        "evidence": f"WinRM error: {str(err)[:200]}",
        "remediation": (
            "Verify WinRM is enabled on target (Test-WSMan from another box), confirm "
            "port + credentials, and check options.use_ssl matches target config "
            "(5986+SSL true / 5985 HTTP)."
        ),
        "cwe": "CWE-1006",
    }


def rule_pywinrm_missing(s):
    if not s.get("winpeas_pywinrm_missing"):
        return None
    return {
        "name": "pywinrm library not installed on scanner host",
        "severity": "INFO",
        "evidence": "Python `winrm` module import failed; cannot execute remote WinPEAS.",
        "remediation": "Install pywinrm: `pip install pywinrm` (already pinned in requirements.txt).",
        "cwe": "CWE-1006",
    }


def rule_winpeas_missing(s):
    if not s.get("winpeas_binary_missing"):
        return None
    return {
        "name": "WinPEAS binary not found on scanner host",
        "severity": "INFO",
        "evidence": ("/opt/peass-ng/winPEAS/winPEASexe/binaries/Release/x64/"
                     "winPEASany.exe missing on backend container."),
        "remediation": ("Re-clone PEASS-ng: git clone https://github.com/peass-ng/PEASS-ng "
                        "/opt/peass-ng (precompiled WinPEAS .exe ships in the release zip)."),
        "cwe": "CWE-1006",
    }


def rule_positive(s):
    if not s.get("winpeas_ran"):
        return None
    if _hits(s, "CRITICAL") or _hits(s, "HIGH") or _hits(s, "MEDIUM"):
        return None
    return {
        "name": "WinPEAS audit clean - no HIGH/CRITICAL privesc vectors detected",
        "severity": "POSITIVE",
        "evidence": (f"WinPEAS ran on {s.get('winpeas_host', 'target')} and returned "
                     "zero HIGH/CRITICAL findings."),
        "remediation": ("Maintain monthly Windows patch cycle + GPO baseline review. "
                        "Re-run WinPEAS after major change windows."),
        "cwe": "CWE-269",
        "owasp": "A01:2021",
    }


WINPEAS_CHECK_FINDING_RULES = [
    rule_critical,
    rule_high,
    rule_medium,
    rule_no_creds,
    rule_winrm_failed,
    rule_pywinrm_missing,
    rule_winpeas_missing,
    rule_positive,
]
