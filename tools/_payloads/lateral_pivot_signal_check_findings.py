"""lateral_pivot_signal_check - findings rules.

Severity model:
  CRITICAL - bogus hash UNEXPECTEDLY authenticated (means real-world misconfig)
  INFO     - normal auth-failure path (expected); customer must verify 4625 alert
  LOW      - many methods exercised (broader attack-surface signal)
  POSITIVE - all methods exercised + auth failed cleanly (good baseline)
"""


def rule_critical_auth_success(s):
    if not s.get("lateral_pivot_critical"):
        return None
    target = s.get("lateral_pivot_target") or "?"
    return {
        "name": (f"CRITICAL: bogus NT hash authenticated successfully against "
                  f"{target} — likely empty-password admin account"),
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-521",
        "owasp": "A07:2021",
        "evidence": (
            "VulnusLab attempted lateral-movement signals with a WELL-KNOWN BOGUS "
            "NT hash (aad3b435...:31d6cfe0... = LM-empty + NT-empty). This hash "
            "should never authenticate. It did, meaning a real account on the "
            f"target ({target}) has an empty/blank password."
        ),
        "remediation": (
            "1. IMMEDIATELY rotate the local Administrator password on the target. "
            "2. Enforce a domain GPO blocking blank passwords: "
            "Computer Config > Windows Settings > Security Settings > "
            "Account Policies > Password Policy > Minimum password length = 14. "
            "3. Audit for other accounts with the same hash via secretsdump.py + "
            "compare-hash. "
            "4. Re-run this probe; AUTH_SUCCEEDED outcome should flip to "
            "AUTH_FAILED_AS_EXPECTED."
        ),
        "mitre_techniques": ["T1078", "T1550.002"],
    }


def rule_signal_rollup(s):
    results = s.get("lateral_pivot_results") or []
    if not results:
        return None
    target = s.get("lateral_pivot_target") or "?"
    domain = s.get("lateral_pivot_domain") or "WORKGROUP"
    user = s.get("lateral_pivot_user") or "Administrator"
    auth_failures = int(s.get("lateral_pivot_auth_failures") or 0)
    net_issues = int(s.get("lateral_pivot_network_issues") or 0)
    methods = s.get("lateral_pivot_methods_run") or []

    sev = "LOW" if len(methods) >= 3 else "INFO"
    return {
        "name": (f"Lateral-movement detection signals emitted: "
                  f"{len(results)} attempts against {target} "
                  f"({auth_failures} auth-failed as expected, "
                  f"{net_issues} network issues)"),
        "severity": sev,
        "cwe": "CWE-693",
        "owasp": "A09:2021",
        "evidence": (
            f"VulnusLab ran impacket primitives ({', '.join(methods)}) against "
            f"{target} as {domain}/{user} with a known-bogus NT hash. "
            "Auth WILL fail (by design); the goal is to emit Windows Security "
            "events 4624 (logon attempt), 4625 (failed logon), 4648 (explicit "
            "creds), and 5140 (network share access)."
        ),
        "remediation": (
            "1. Pull the Windows Security log on the target during the test window. "
            f"Expected event chain: 4648 -> 4624 (type=3 Network) -> 4625 (failure "
            f"reason 0xC000006D bad credentials). LogonAccount={user}, "
            f"SourceWorkstation=<VulnusLab-egress>. "
            "2. If your SIEM didn't alert: build/enable Sigma rule "
            "'win_susp_failed_logon_reasons.yml' or Splunk SPL "
            "EventCode=4625 LogonType=3 | stats count by ComputerName Account_Name. "
            "3. Set thresholds: >5 failed-logons in <60s from same source = alert. "
            "4. For DCOM/WMI lateral movement, also enable WMI activity logs "
            "(EventID 5857-5861 in Microsoft-Windows-WMI-Activity/Operational). "
            "5. Re-run quarterly; the bogus-hash auth-failure event should keep "
            "firing the alert consistently."
        ),
        "mitre_techniques": ["T1078", "T1550.002", "T1570", "T1021.002", "T1021.006"],
        "references": [
            "https://attack.mitre.org/techniques/T1550/002/",
            "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625",
            "https://github.com/SigmaHQ/sigma/tree/master/rules/windows/builtin/security",
        ],
    }


def rule_input_missing(s):
    if not s.get("lateral_input_missing"):
        return None
    return {
        "name": "Lateral pivot signal check skipped - lateral_target not supplied",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": ("Probe needs options.lateral_target = customer LAN IP "
                     "running a Windows / SMB service."),
        "remediation": (
            "Re-run with options.lateral_target = <customer LAN IP>, optionally "
            "options.lateral_domain, options.lateral_user. The default NT hash "
            "is deliberately invalid so no real authentication can occur."
        ),
    }


def rule_input_invalid(s):
    err = s.get("lateral_input_invalid")
    if not err:
        return None
    return {
        "name": f"Lateral pivot check skipped - invalid input: {err[:80]}",
        "severity": "INFO",
        "cwe": "CWE-1287",
        "evidence": f"Validation error: {err}",
        "remediation": "Re-run with options.lateral_target = IPv4 address.",
    }


def rule_binary_missing(s):
    missing = s.get("lateral_pivot_missing_bins") or []
    if not missing:
        return None
    return {
        "name": (f"Impacket binaries missing: {', '.join(missing)} - "
                  "test signals partial"),
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": ("These impacket-* binaries were not found in PATH: "
                     + ", ".join(missing) + "."),
        "remediation": (
            "Install impacket: pip install impacket (already in VulnusLab image; "
            "rebuild VPS if you see this in production). Verify with "
            "`which impacket-psexec impacket-wmiexec impacket-smbexec`."
        ),
    }


def rule_positive(s):
    if s.get("lateral_pivot_critical"):
        return None
    if s.get("lateral_input_missing") or s.get("lateral_input_invalid"):
        return None
    total = int(s.get("lateral_pivot_total") or 0)
    if not total:
        return None
    auth_failures = int(s.get("lateral_pivot_auth_failures") or 0)
    if auth_failures < total:
        return None  # some methods didn't run cleanly
    return {
        "name": f"All {total} lateral-pivot attempts auth-failed cleanly (good baseline)",
        "severity": "POSITIVE",
        "evidence": (f"All {total} method(s) returned AUTH_FAILED_AS_EXPECTED. "
                     "The target IS responding to SMB/WMI/WinRM connect attempts, "
                     "but rejects the bogus hash — exactly the expected outcome. "
                     "Now your SIEM/EDR should have logged 4625 events."),
        "remediation": (
            "Network path open + auth-deny working = good. Confirm your SIEM "
            "saw the 4625 burst. If not, that's a detection gap."
        ),
        "cwe": "CWE-693",
        "owasp": "A09:2021",
    }


LATERAL_PIVOT_SIGNAL_CHECK_FINDING_RULES = [
    rule_critical_auth_success,
    rule_signal_rollup,
    rule_input_missing,
    rule_input_invalid,
    rule_binary_missing,
    rule_positive,
]
