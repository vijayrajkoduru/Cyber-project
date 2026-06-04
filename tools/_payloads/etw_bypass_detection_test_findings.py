"""etw_bypass_detection_test - findings rules.

Severity model (FLIPPED vs. normal convention):

  HIGH      EDR did NOT block / alert on the EventProvider reflection +
            EtwEventWrite P/Invoke combo -> ETW visibility gap.
  POSITIVE  EDR blocked / killed the probe -> good ETW patch detection.
  INFO      Probe could not run / partial result.
"""


def rule_high_etw_gap(s):
    if not s.get("etw_bypass_baseline_ok"):
        return None
    if s.get("etw_bypass_blocked"):
        return None
    # We need BOTH the EventProvider reflection AND the P/Invoke compile
    # to confirm the chain ran end-to-end.
    if not s.get("etw_bypass_type_resolved"):
        return None
    if not s.get("etw_bypass_field_resolved"):
        return None
    if not s.get("etw_bypass_pinvoke_compiled"):
        return None
    return {
        "name": "ETW patch primitive ran undetected on Windows host",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-693",
        "owasp": "A05:2021",
        "mitre": "T1562.006",
        "evidence": (
            "The public ETW patch primitive (reflection on "
            "[System.Diagnostics.Eventing.EventProvider].m_enabled "
            "non-public field) AND a P/Invoke signature against "
            "ntdll!EtwEventWrite both ran successfully via WinRM. "
            "Neither AMSI nor the EDR's reflection / P/Invoke rule "
            "triggered. (No fields were mutated - SetValue was deliberately "
            "skipped - so ETW is still healthy; only the detection chain "
            "was tested.)"
        ),
        "remediation": (
            "1. Confirm the EDR agent has ETW-TI (Threat Intelligence) "
            "integration enabled. Defender ATP: `Get-MpComputerStatus | "
            "Select-Object AMRunningMode, AntivirusEnabled, "
            "RealTimeProtectionEnabled`. 2. Add a Sigma / Splunk / Sentinel "
            "rule on PowerShell Operational Event ID 4104 for the strings "
            "'System.Diagnostics.Eventing.EventProvider', 'm_enabled', "
            "'EtwEventWrite', 'GetField.*NonPublic.*Instance'. "
            "3. Forward Microsoft-Windows-Threat-Intelligence ETW channel "
            "events to your SIEM - they catch most ETW patch attempts "
            "from kernel-mode. 4. Re-run this probe after fixes. If still "
            "no detection, escalate to vendor."
        ),
    }


def rule_positive_edr_caught(s):
    if not s.get("etw_bypass_blocked"):
        return None
    return {
        "name": "ETW patch primitive caught and blocked by EDR",
        "severity": "POSITIVE",
        "evidence": (
            "Reflection access on EventProvider.m_enabled OR the "
            "ntdll!EtwEventWrite P/Invoke compilation was blocked by "
            "AMSI / Defender / EDR. The customer's runtime detection for "
            "the canonical ETW patch chain is functional on this host."
        ),
        "remediation": (
            "1. Schedule a weekly automated run of this probe to catch "
            "regression after signature updates. 2. Forward AMSI / EDR "
            "block events to SIEM with a high-severity alert. 3. Add the "
            "Sigma rule for the reflection strings anyway as defense in "
            "depth."
        ),
        "cwe": "CWE-693",
        "owasp": "A05:2021",
        "mitre": "T1562.006",
    }


def rule_partial(s):
    if s.get("etw_bypass_blocked"):
        return None
    if not s.get("etw_bypass_baseline_ok"):
        return None
    # If baseline ran but the bypass chain didn't fully complete AND the
    # EDR didn't visibly block, flag as INFO (likely Constrained Language
    # Mode or .NET sandbox).
    if (s.get("etw_bypass_type_resolved") and
        s.get("etw_bypass_field_resolved") and
        s.get("etw_bypass_pinvoke_compiled")):
        return None
    if s.get("etw_bypass_creds_missing"):
        return None
    if s.get("etw_bypass_winrm_auth_failed"):
        return None
    if s.get("etw_bypass_detection_test_error"):
        return None
    return {
        "name": "ETW probe ran partially - chain did not complete",
        "severity": "INFO",
        "evidence": (
            "Baseline shell ran but the EventProvider reflection or "
            "EtwEventWrite P/Invoke step did not produce the expected "
            "marker. No explicit EDR block was observed. Likely cause: "
            "Constrained Language Mode forced on the account, or "
            ".NET Add-Type sandboxing. Summary: "
            + str(s.get("etw_bypass_summary") or "")[:300]
        ),
        "remediation": (
            "1. If Constrained Language Mode is forced on the audit "
            "account (`$ExecutionContext.SessionState.LanguageMode -eq "
            "'ConstrainedLanguage'`), that is GOOD defensive posture but "
            "this probe can't measure ETW detection. Use a different "
            "non-CLM account for the probe and re-run. 2. Verify Add-Type "
            "is not blocked by AppLocker / WDAC."
        ),
        "cwe": "CWE-693",
    }


def rule_creds_missing(s):
    if not s.get("etw_bypass_creds_missing"):
        return None
    return {
        "name": "ETW bypass detection probe skipped - WinRM credentials missing",
        "severity": "INFO",
        "evidence": ("This probe requires options.username + options.password. "
                     "Without creds no test ran."),
        "remediation": (
            "Re-run with options.username (DOMAIN\\\\user or .\\\\local-acct) "
            "+ options.password. Use a non-Constrained-Language-Mode account."
        ),
        "cwe": "CWE-1006",
    }


def rule_auth_failed(s):
    if not s.get("etw_bypass_winrm_auth_failed"):
        return None
    return {
        "name": "WinRM authentication failed during ETW probe",
        "severity": "INFO",
        "evidence": ("pywinrm reported 401 Unauthorized or NTLM negotiation "
                     "failure with the supplied username/password."),
        "remediation": (
            "Confirm the account is enabled, not locked, and has WinRM "
            "permissions. Check Event ID 4625 for the AuthN failure reason."
        ),
        "cwe": "CWE-287",
    }


def rule_pywinrm_missing(s):
    err = str(s.get("etw_bypass_detection_test_error") or "")
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
    err = str(s.get("etw_bypass_detection_test_error") or "")
    if not err or "pywinrm" in err:
        return None
    if "winrm: " not in err and "winrm timeout" not in err:
        return None
    return {
        "name": "WinRM connection failed during ETW probe",
        "severity": "INFO",
        "evidence": f"Connection error: {err}",
        "remediation": (
            "Verify WinRM is listening on the target, the port is open, "
            "and the scanner IP is trusted."
        ),
        "cwe": "CWE-1006",
    }


ETW_BYPASS_DETECTION_TEST_FINDING_RULES = [
    rule_high_etw_gap,
    rule_positive_edr_caught,
    rule_partial,
    rule_creds_missing,
    rule_auth_failed,
    rule_pywinrm_missing,
    rule_connect_error,
]
