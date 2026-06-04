"""amsi_bypass_detection_test - findings rules.

Severity model (FLIPPED vs. normal VulnusLab convention because this is
a detection-capability probe, not a vulnerability scanner):

  HIGH      EDR did NOT block the AMSI bypass primitive AND the
            follow-up Get-Process succeeded -> customer has a real AMSI
            visibility gap on this Windows host.
  POSITIVE  EDR cleanly blocked the bypass attempt (gold-standard).
  INFO      Probe could not run (no creds / pywinrm missing / WinRM
            failure) OR partial result (bypass blocked but follow-up
            failed for unrelated reasons).
"""


def rule_high_amsi_gap(s):
    """Highest-priority signal: the customer's EDR did NOT catch the
    textbook Matt Graeber AMSI bypass."""
    if not s.get("amsi_bypass_baseline_ok"):
        return None   # baseline failed -> WinRM is unhealthy, don't fire HIGH
    if s.get("amsi_bypass_blocked"):
        return None   # EDR caught it -> POSITIVE
    if not s.get("amsi_bypass_set_true"):
        return None   # bypass primitive didn't even reflect the field
    if not s.get("amsi_bypass_followup_ok"):
        return None   # follow-up didn't run -> can't claim full gap
    return {
        "name": "AMSI bypass primitive ran undetected on Windows host",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-693",
        "owasp": "A05:2021",
        "mitre": "T1562.001",
        "evidence": (
            "Public Matt Graeber AMSI bypass primitive (reflection on "
            "AmsiUtils.amsiInitFailed) was executed via WinRM PowerShell. "
            "The technique was NOT blocked by AMSI / Defender / EDR. "
            "Baseline + follow-up Get-Process commands both ran "
            "successfully after the bypass was submitted. "
            "(Field value was restored after the probe to avoid mutating "
            "host state.)"
        ),
        "remediation": (
            "1. Confirm AMSI is enabled: `Get-MpPreference | Select-Object "
            "DisableScriptScanning, DisableRealtimeMonitoring`. Both should "
            "be False. 2. Verify the EDR agent (Defender ATP / CrowdStrike "
            "Falcon / SentinelOne) is healthy and has AMSI integration "
            "enabled (Defender: `Get-MpComputerStatus`, look for "
            "AMRunningMode=Normal). 3. Add a Sigma rule on PowerShell "
            "Operational Event ID 4104 for the strings "
            "'AmsiUtils', 'amsiInitFailed', '[Ref].Assembly.GetType'. "
            "4. Enable Constrained Language Mode for all non-admin "
            "PowerShell sessions: `[Environment]::SetEnvironmentVariable("
            "'__PSLockdownPolicy','4','Machine')`. "
            "5. Re-run this probe after fixes - if it still fires, escalate "
            "to the EDR vendor as a missed-detection ticket."
        ),
    }


def rule_positive_edr_caught(s):
    if not s.get("amsi_bypass_blocked"):
        return None
    return {
        "name": "AMSI bypass primitive caught and blocked by EDR/AV",
        "severity": "POSITIVE",
        "evidence": (
            "The Matt Graeber AMSI bypass reflection chain was submitted "
            "via WinRM PowerShell and was caught by AMSI / Defender / EDR. "
            "Baseline shell ran cleanly; the bypass step was blocked "
            "(error or rc!=0 with AMSI signature). Customer's runtime "
            "script-block scanning is functional on this host."
        ),
        "remediation": (
            "1. Keep AMSI healthy: schedule a weekly automated run of this "
            "probe to detect regression (Defender signature updates can "
            "occasionally drop a detection). 2. Forward AMSI block events "
            "(Defender Operational Event ID 1116 / 1117) to your SIEM with "
            "a high-severity alert. 3. Consider adding the Sigma rule for "
            "the bypass string anyway - belt-and-braces detection."
        ),
        "cwe": "CWE-693",
        "owasp": "A05:2021",
        "mitre": "T1562.001",
    }


def rule_partial_baseline_failed(s):
    if s.get("amsi_bypass_baseline_ok"):
        return None
    if s.get("amsi_bypass_creds_missing"):
        return None
    if s.get("amsi_bypass_winrm_auth_failed"):
        return None
    if s.get("amsi_bypass_detection_test_error"):
        return None
    return {
        "name": "AMSI probe baseline shell did not respond",
        "severity": "INFO",
        "evidence": (
            "WinRM session opened but the baseline `Get-Process` command "
            "did not return the expected marker. Cannot reliably attribute "
            "subsequent bypass step results to EDR behaviour vs. shell "
            "issues. Summary: " + str(s.get("amsi_bypass_summary") or "")[:300]
        ),
        "remediation": (
            "Re-run with a healthy WinRM session. Check whether the "
            "supplied account has Constrained Language Mode forced "
            "(`$ExecutionContext.SessionState.LanguageMode`) which would "
            "block the [Ref].Assembly reflection used by this probe."
        ),
        "cwe": "CWE-1006",
    }


def rule_creds_missing(s):
    if not s.get("amsi_bypass_creds_missing"):
        return None
    return {
        "name": "AMSI bypass detection probe skipped - WinRM credentials missing",
        "severity": "INFO",
        "evidence": ("This probe requires options.username + options.password "
                     "to WinRM into the target. Without creds no test ran."),
        "remediation": (
            "Re-run with options.username (DOMAIN\\\\user or .\\\\local-acct) "
            "+ options.password. Recommended: create a read-only audit "
            "account with `Remote Management Users` group membership."
        ),
        "cwe": "CWE-1006",
    }


def rule_auth_failed(s):
    if not s.get("amsi_bypass_winrm_auth_failed"):
        return None
    return {
        "name": "WinRM authentication failed during AMSI probe",
        "severity": "INFO",
        "evidence": ("pywinrm reported 401 Unauthorized or NTLM negotiation "
                     "failure with the supplied username/password."),
        "remediation": (
            "Confirm the account is enabled, not locked, and has WinRM "
            "permissions (`Get-PSSessionConfiguration | Set-PSSessionConfiguration "
            "... -ShowSecurityDescriptorUI`). Check Event ID 4625 on the "
            "target for the AuthN failure reason."
        ),
        "cwe": "CWE-287",
    }


def rule_pywinrm_missing(s):
    err = str(s.get("amsi_bypass_detection_test_error") or "")
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
    err = str(s.get("amsi_bypass_detection_test_error") or "")
    if not err or "pywinrm" in err:
        return None
    if "winrm: " not in err and "winrm timeout" not in err:
        return None
    return {
        "name": "WinRM connection failed during AMSI probe",
        "severity": "INFO",
        "evidence": f"Connection error: {err}",
        "remediation": (
            "Verify WinRM is listening on the target (`winrm quickconfig` + "
            "`Test-WSMan <host>`), the port (5985 / 5986) is open, and the "
            "scanner IP is in the TrustedHosts list."
        ),
        "cwe": "CWE-1006",
    }


AMSI_BYPASS_DETECTION_TEST_FINDING_RULES = [
    rule_high_amsi_gap,
    rule_positive_edr_caught,
    rule_partial_baseline_failed,
    rule_creds_missing,
    rule_auth_failed,
    rule_pywinrm_missing,
    rule_connect_error,
]
