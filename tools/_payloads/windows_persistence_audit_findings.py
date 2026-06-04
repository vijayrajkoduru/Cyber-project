"""windows_persistence_audit - findings rules.

Severity model:
  HIGH      malicious patterns (powershell -enc / IEX / IFEO debugger /
            AppInit_DLL enabled / user-writable Run target / WMI consumer
            with cscript-wscript-mshta-rundll32)
  MEDIUM    non-baseline entries (third-party task author, non-system
            service path)
  INFO      WinRM creds missing / pywinrm missing / connection failed
  POSITIVE  audit ran and every entry matched a Microsoft-signed baseline
"""


def rule_high(s):
    hits = s.get("windows_persistence_high_hits") or []
    if not hits:
        return None
    categories = sorted({h.get("category") for h in hits if h.get("category")})
    patterns = sorted({h.get("pattern") for h in hits if h.get("pattern")})
    sample = "; ".join(
        f"{h.get('category')}: {(h.get('value') or h.get('action') or h.get('path') or h.get('debugger') or '')[:80]}"
        for h in hits[:3]
    )
    return {
        "name": (f"Windows persistence attacker artifacts detected "
                 f"({len(hits)} suspicious entries across "
                 f"{', '.join(categories)})"),
        "severity": "HIGH",
        "cvss": "8.8",
        "cwe": "CWE-506",
        "owasp": "A05:2021",
        "mitre": "T1547.001, T1053.005, T1546.012, T1546.010, T1546.003",
        "evidence": (f"Pattern types triggered: {', '.join(patterns)}. "
                     f"Examples: {sample}"),
        "remediation": (
            "1. Isolate the host from the network and capture a memory image "
            "with WinPMem/DumpIt. 2. Decode every powershell -enc blob found "
            "(`[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('...'))`) "
            "and pivot from the URLs/IPs revealed. 3. Remove every flagged "
            "entry; for IFEO and AppInit_DLLs use `reg delete`. 4. Rotate the "
            "service account passwords + the local Administrator password. "
            "5. Rebuild from gold image - attacker likely planted multiple "
            "redundant persistence layers (T1547 + T1053 + T1546 chained)."
        ),
    }


def rule_medium(s):
    hits = s.get("windows_persistence_medium_hits") or []
    if not hits:
        return None
    categories = sorted({h.get("category") for h in hits if h.get("category")})
    return {
        "name": (f"Non-baseline Windows persistence entries "
                 f"({len(hits)} entries in {', '.join(categories)})"),
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-506",
        "owasp": "A05:2021",
        "mitre": "T1547.001, T1053.005, T1543.003",
        "evidence": (
            f"{len(hits)} entries are present on persistence surfaces but do "
            "not match a stock Microsoft-signed baseline (third-party task "
            "author, non-system service path, etc.). These may be legitimate "
            "vendor agents (Crowdstrike, AV, Splunk) or attacker plants."
        ),
        "remediation": (
            "1. For each entry, confirm with asset owner whether the author / "
            "path corresponds to an approved vendor agent. 2. Sign and "
            "fingerprint every legitimate non-MS entry into your baseline. "
            "3. Forward Sysmon Event ID 11 (FileCreate), 12/13/14 (registry), "
            "and Schtasks events to your SIEM so future additions trigger "
            "alerts."
        ),
    }


def rule_creds_missing(s):
    if not s.get("windows_persistence_creds_missing"):
        return None
    return {
        "name": "Windows persistence audit skipped - WinRM credentials not supplied",
        "severity": "INFO",
        "evidence": ("This probe requires options.username + options.password "
                     "to WinRM into the target. Without creds no audit ran."),
        "remediation": (
            "Re-run with options.username (DOMAIN\\\\user or .\\\\local-acct) "
            "+ options.password. Recommended: create a read-only audit account "
            "with `Remote Management Users` group membership and a long random "
            "password pinned in your VulnusLab credentials vault. Use "
            "options.use_ssl=true + port 5986 to keep creds off the wire in "
            "cleartext."
        ),
        "cwe": "CWE-1006",
    }


def rule_auth_failed(s):
    if not s.get("windows_persistence_winrm_auth_failed"):
        return None
    return {
        "name": "WinRM authentication failed during persistence audit",
        "severity": "INFO",
        "evidence": ("pywinrm reported 401 Unauthorized or NTLM negotiation "
                     "failure with the supplied username/password."),
        "remediation": (
            "Confirm the account is enabled, not locked, and has WinRM "
            "permissions (`Remote Management Users` group + `Get-PSSessionConfiguration "
            "| Set-PSSessionConfiguration ... -ShowSecurityDescriptorUI`). "
            "Check Event ID 4625 on the target for the AuthN failure reason."
        ),
        "cwe": "CWE-287",
    }


def rule_pywinrm_missing(s):
    err = str(s.get("windows_persistence_audit_error") or "")
    if "pywinrm not installed" not in err:
        return None
    return {
        "name": "pywinrm library not installed on scanner host",
        "severity": "INFO",
        "evidence": "import winrm failed. Probe could not execute.",
        "remediation": "pip install pywinrm (already part of Kali base image).",
        "cwe": "CWE-1006",
    }


def rule_connect_error(s):
    err = str(s.get("windows_persistence_audit_error") or "")
    if not err or "pywinrm" in err:
        return None
    if "winrm: " not in err and "winrm timeout" not in err:
        return None
    return {
        "name": "WinRM connection failed during persistence audit",
        "severity": "INFO",
        "evidence": f"Connection error: {err}",
        "remediation": (
            "Verify WinRM is listening on the target "
            "(`winrm quickconfig` + `Test-WSMan <host>`), the port (5985 / "
            "5986) is open in the firewall, and the scanner IP is in the "
            "TrustedHosts list (`Set-Item WSMan:\\localhost\\Client\\TrustedHosts`). "
            "Re-run once Test-WSMan returns a response."
        ),
        "cwe": "CWE-1006",
    }


def rule_positive(s):
    if s.get("windows_persistence_audit_total"):
        return None
    if s.get("windows_persistence_creds_missing"):
        return None
    if s.get("windows_persistence_winrm_auth_failed"):
        return None
    if s.get("windows_persistence_audit_error"):
        return None
    counts = s.get("windows_persistence_counts") or {}
    if not counts:
        return None
    return {
        "name": "Windows persistence surface clean (no suspicious entries)",
        "severity": "POSITIVE",
        "evidence": (
            f"Enumerated {sum(counts.values())} entries across Run keys, "
            "scheduled tasks, services, WMI subscriptions, IFEO, and "
            "AppInit_DLLs. All matched a Microsoft-signed baseline. "
            f"Breakdown: {counts}."
        ),
        "remediation": (
            "Continue running this audit weekly. Enable Sysmon (Olaf Hartong "
            "config) + ship to SIEM so future persistence additions trigger "
            "real-time alerts on Event IDs 11/12/13/14/19/20/21."
        ),
        "cwe": "CWE-506",
        "owasp": "A05:2021",
    }


WINDOWS_PERSISTENCE_AUDIT_FINDING_RULES = [
    rule_high,
    rule_medium,
    rule_creds_missing,
    rule_auth_failed,
    rule_pywinrm_missing,
    rule_connect_error,
    rule_positive,
]
