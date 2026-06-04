"""process_hollowing_detection_test - findings rules.

Severity model (FLIPPED vs. normal convention):

  HIGH      The full process-hollowing API sequence (CreateProcess
            SUSPENDED + ZwUnmapViewOfSection + WriteProcessMemory +
            ResumeThread) executed end-to-end without EDR detection.
            Attackers using textbook hollowing will go undetected.
  POSITIVE  EDR blocked the chain (typically before or at ResumeThread).
  INFO      Probe couldn't run / partial result.
"""


def rule_high_hollowing_undetected(s):
    if s.get("process_hollowing_blocked_by_edr"):
        return None
    # The full chain must have completed cleanly.
    if not s.get("process_hollowing_pinvoke_compiled"):
        return None
    if not s.get("process_hollowing_create_ok"):
        return None
    if not s.get("process_hollowing_unmap_attempted"):
        return None
    if not s.get("process_hollowing_write_ok"):
        return None
    if not s.get("process_hollowing_resume_ok"):
        return None
    return {
        "name": "Process Hollowing API sequence ran undetected on Windows host",
        "severity": "HIGH",
        "cvss": "8.2",
        "cwe": "CWE-693",
        "owasp": "A05:2021",
        "mitre": "T1055.012",
        "evidence": (
            "The canonical process-hollowing call chain was executed via "
            "WinRM PowerShell + P/Invoke against suspended notepad.exe "
            f"(PID {s.get('process_hollowing_create_pid') or '?'}):\n"
            "  CreateProcessW(SUSPENDED) -> ZwUnmapViewOfSection -> "
            "ReadProcessMemory -> WriteProcessMemory (original bytes) -> "
            "ResumeThread -> TerminateProcess.\n"
            "EDR did NOT block any step. (The notepad process was created "
            "suspended, the same bytes were written back to its image base "
            "(no payload was injected), and the process was terminated "
            "immediately so no UI was shown.)"
        ),
        "remediation": (
            "1. Confirm the EDR agent has process-injection / "
            "process-hollowing rules enabled. Defender ATP: enable "
            "Attack Surface Reduction rule "
            "'Block process creations originating from PSExec and WMI "
            "commands' (b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4) and "
            "'Block credential stealing from the Windows local security "
            "authority subsystem' (9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2). "
            "2. Add a Sysmon rule for Event ID 8 (CreateRemoteThread) and "
            "Event ID 10 (ProcessAccess with GrantedAccess 0x1F0FFF, the "
            "PROCESS_VM_OPERATION+PROCESS_VM_WRITE+PROCESS_SUSPEND combo). "
            "3. Verify ETW Microsoft-Windows-Kernel-Process events 1+5 are "
            "forwarded to SIEM with alerts on suspended-process creations "
            "that aren't from known-good launchers. "
            "4. Re-run this probe; if still undetected, escalate to EDR "
            "vendor as a missed-detection ticket with this evidence block."
        ),
    }


def rule_positive_edr_caught(s):
    if not s.get("process_hollowing_blocked_by_edr"):
        return None
    return {
        "name": "Process Hollowing API sequence blocked by EDR",
        "severity": "POSITIVE",
        "evidence": (
            "The CreateProcess(SUSPENDED) + ZwUnmapViewOfSection + "
            "WriteProcessMemory + ResumeThread chain was killed by "
            "the EDR during execution. Customer's process-injection "
            "detection ruleset is functional on this host."
        ),
        "remediation": (
            "1. Schedule weekly automated re-run to catch regression. "
            "2. Forward EDR block events to SIEM with a high-severity "
            "alert. 3. Consider testing additional injection variants "
            "(Thread hijack T1055.003, APC T1055.004, Reflective DLL "
            "T1055.001) in future module releases."
        ),
        "cwe": "CWE-693",
        "owasp": "A05:2021",
        "mitre": "T1055.012",
    }


def rule_partial(s):
    if s.get("process_hollowing_blocked_by_edr"):
        return None
    # Already-complete chain handled by rule_high above.
    if (s.get("process_hollowing_pinvoke_compiled") and
        s.get("process_hollowing_create_ok") and
        s.get("process_hollowing_unmap_attempted") and
        s.get("process_hollowing_write_ok") and
        s.get("process_hollowing_resume_ok")):
        return None
    if s.get("process_hollowing_creds_missing"):
        return None
    if s.get("process_hollowing_winrm_auth_failed"):
        return None
    if s.get("process_hollowing_detection_test_error"):
        return None
    if not s.get("process_hollowing_pinvoke_compiled"):
        return None
    # Chain started but did not complete and no explicit EDR signature.
    return {
        "name": "Process Hollowing chain did not complete (partial probe)",
        "severity": "INFO",
        "evidence": (
            "P/Invoke compiled but the full call chain did not reach "
            "ResumeThread. No EDR block signature observed - may be "
            "Constrained Language Mode, AppLocker, or a transient "
            "Win32 error. Summary: "
            + str(s.get("process_hollowing_summary") or "")[:300]
        ),
        "remediation": (
            "1. Confirm the audit account is in FullLanguage mode "
            "(`$ExecutionContext.SessionState.LanguageMode`). "
            "2. Confirm AppLocker isn't blocking Add-Type / dynamic "
            "P/Invoke. 3. Re-run."
        ),
        "cwe": "CWE-693",
    }


def rule_creds_missing(s):
    if not s.get("process_hollowing_creds_missing"):
        return None
    return {
        "name": "Process hollowing detection probe skipped - WinRM credentials missing",
        "severity": "INFO",
        "evidence": ("This probe requires options.username + options.password. "
                     "Without creds no test ran."),
        "remediation": (
            "Re-run with options.username + options.password populated."
        ),
        "cwe": "CWE-1006",
    }


def rule_auth_failed(s):
    if not s.get("process_hollowing_winrm_auth_failed"):
        return None
    return {
        "name": "WinRM authentication failed during process hollowing probe",
        "severity": "INFO",
        "evidence": ("pywinrm reported 401 Unauthorized or NTLM negotiation "
                     "failure."),
        "remediation": (
            "Confirm the account is enabled, not locked, and has WinRM "
            "permissions."
        ),
        "cwe": "CWE-287",
    }


def rule_pywinrm_missing(s):
    err = str(s.get("process_hollowing_detection_test_error") or "")
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
    err = str(s.get("process_hollowing_detection_test_error") or "")
    if not err or "pywinrm" in err:
        return None
    if "winrm: " not in err and "winrm timeout" not in err:
        return None
    return {
        "name": "WinRM connection failed during process hollowing probe",
        "severity": "INFO",
        "evidence": f"Connection error: {err}",
        "remediation": (
            "Verify WinRM is listening, the port is open, and the scanner "
            "IP is trusted."
        ),
        "cwe": "CWE-1006",
    }


PROCESS_HOLLOWING_DETECTION_TEST_FINDING_RULES = [
    rule_high_hollowing_undetected,
    rule_positive_edr_caught,
    rule_partial,
    rule_creds_missing,
    rule_auth_failed,
    rule_pywinrm_missing,
    rule_connect_error,
]
