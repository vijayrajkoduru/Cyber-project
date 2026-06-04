"""direct_syscall_detection_test - findings rules.

Severity model (FLIPPED vs. normal convention):

  HIGH      The direct (inline) syscall stub for NtAllocateVirtualMemory
            executed successfully WITHOUT EDR detection. This means the
            customer's EDR is relying on userland inline hooks in
            ntdll.dll for visibility - which is bypassed by the inline
            `syscall` instruction. Modern offensive tooling (Hells Gate,
            SysWhispers3) will go undetected.
  POSITIVE  EDR blocked the chain (caught the RWX allocation, the stub
            write, or the syscall pattern via kernel-mode telemetry).
  INFO      Probe couldn't run / partial result.
"""


def rule_high_direct_undetected(s):
    if s.get("direct_syscall_blocked_by_edr"):
        return None
    if not s.get("direct_syscall_pinvoke_compiled"):
        return None
    if not s.get("direct_syscall_baseline_ok"):
        return None
    if not s.get("direct_syscall_ssn_resolved"):
        return None
    if not s.get("direct_syscall_stub_written"):
        return None
    if not s.get("direct_syscall_direct_ok"):
        return None
    return {
        "name": "Direct syscall (inline `syscall` instruction) executed undetected",
        "severity": "HIGH",
        "cvss": "8.2",
        "cwe": "CWE-693",
        "owasp": "A05:2021",
        "mitre": "T1106, T1620",
        "evidence": (
            f"Resolved SSN (syscall number) "
            f"{s.get('direct_syscall_ssn_value') or '?'} for "
            "NtAllocateVirtualMemory from ntdll.dll, assembled an 11-byte "
            "inline syscall stub (mov r10,rcx ; mov eax,SSN ; syscall ; ret), "
            "wrote it to RWX memory, and invoked it via a delegate to "
            "allocate + free 4 KB of RW memory. The direct-syscall path "
            "succeeded "
            f"(status {s.get('direct_syscall_direct_status') or '?'}). "
            "EDR did NOT block any step. Userland-hook-only EDR products "
            "(some legacy AV configs, default Defender without "
            "Microsoft-Windows-Threat-Intelligence ETW) are blind to this "
            "technique."
        ),
        "remediation": (
            "1. Confirm the EDR has kernel-mode telemetry enabled - userland "
            "ntdll inline hooks are NOT sufficient against inline syscalls. "
            "Defender ATP: ensure Microsoft-Windows-Threat-Intelligence ETW "
            "channel is enabled (`Get-WinEvent -ListLog Microsoft-Windows-"
            "Threat-Intelligence`). CrowdStrike / SentinelOne: enable "
            "kernel callback registration. 2. Add a Sysmon rule for Event "
            "ID 8 (CreateRemoteThread) and 10 (ProcessAccess) on RWX "
            "allocations originating from PowerShell.exe with a delegate "
            "GetDelegateForFunctionPointer pattern. 3. Disable RWX page "
            "allocation in PowerShell session policies if business-allowed. "
            "4. Re-run this probe; if still undetected, escalate as a "
            "vendor missed-detection."
        ),
    }


def rule_positive_edr_caught(s):
    if not s.get("direct_syscall_blocked_by_edr"):
        return None
    return {
        "name": "Direct syscall stub blocked by EDR",
        "severity": "POSITIVE",
        "evidence": (
            "The RWX allocation, inline-stub write, or the actual `syscall` "
            "execution was blocked by EDR / AV. Customer's defence covers "
            "the modern Hells-Gate / SysWhispers3 evasion pattern."
        ),
        "remediation": (
            "1. Schedule weekly automated re-run. 2. Forward EDR block "
            "events to SIEM with a high-severity alert. 3. Consider "
            "testing indirect syscalls (call into ntdll's syscall "
            "instruction without inline copying) as a follow-up probe in "
            "future module releases."
        ),
        "cwe": "CWE-693",
        "owasp": "A05:2021",
        "mitre": "T1106",
    }


def rule_baseline_ok_direct_failed(s):
    """Subtle case: baseline P/Invoke works but the direct syscall fails
    WITHOUT a recognised EDR-block signature. Could be: SSN resolution
    failure on a non-standard ntdll build (Wine, ReactOS, sandbox), or
    a silent hook that just returns non-zero. Flag MEDIUM-ish as INFO."""
    if s.get("direct_syscall_blocked_by_edr"):
        return None
    if not s.get("direct_syscall_baseline_ok"):
        return None
    if s.get("direct_syscall_direct_ok"):
        return None   # handled above
    # Need at least SSN resolution + stub-written to even attempt
    if not s.get("direct_syscall_ssn_resolved"):
        return None
    if not s.get("direct_syscall_stub_written"):
        return None
    return {
        "name": "Baseline NtAlloc works but direct syscall path failed without EDR block signature",
        "severity": "INFO",
        "evidence": (
            "The standard P/Invoke NtAllocateVirtualMemory call succeeded "
            f"(status {s.get('direct_syscall_baseline_status') or '?'}), "
            "and the inline syscall stub was written to RWX memory, but "
            "the direct-syscall invocation did not allocate a region "
            "(addr=0). No recognised AV / EDR signature triggered. This "
            "could indicate (a) a silent hook that returns failure without "
            "explicit message, (b) a non-standard SSN on this Windows "
            "build, or (c) CFG (Control Flow Guard) blocking the indirect "
            "call. Summary: "
            + str(s.get("direct_syscall_summary") or "")[:300]
        ),
        "remediation": (
            "1. Check the EDR vendor's behavioural-detection telemetry "
            "(CrowdStrike Falcon -> Endpoint Detections, look for silent "
            "kill events around the time of this scan). 2. Confirm CFG "
            "and Control-flow Enforcement Technology (CET) are enabled on "
            "this build (`Get-ProcessMitigation -System | Select-Object "
            "ControlFlowGuard, UserShadowStack`). 3. If both are clean, "
            "re-run on a different Windows build to verify SSN value."
        ),
        "cwe": "CWE-693",
    }


def rule_baseline_failed(s):
    if s.get("direct_syscall_blocked_by_edr"):
        return None
    if s.get("direct_syscall_creds_missing"):
        return None
    if s.get("direct_syscall_winrm_auth_failed"):
        return None
    if s.get("direct_syscall_detection_test_error"):
        return None
    if s.get("direct_syscall_baseline_ok"):
        return None
    if not s.get("direct_syscall_pinvoke_compiled"):
        return None
    return {
        "name": "Direct syscall probe baseline failed (P/Invoke NtAlloc unreachable)",
        "severity": "INFO",
        "evidence": (
            "P/Invoke compiled but the BASELINE NtAllocateVirtualMemory "
            "call did not return a valid allocation. Cannot conclude EDR "
            "behaviour on the inline-syscall step. Summary: "
            + str(s.get("direct_syscall_summary") or "")[:300]
        ),
        "remediation": (
            "Verify the audit account has user-mode allocation rights. "
            "Confirm AppLocker / WDAC isn't blocking dynamic P/Invoke."
        ),
        "cwe": "CWE-693",
    }


def rule_creds_missing(s):
    if not s.get("direct_syscall_creds_missing"):
        return None
    return {
        "name": "Direct syscall detection probe skipped - WinRM credentials missing",
        "severity": "INFO",
        "evidence": ("This probe requires options.username + options.password. "
                     "Without creds no test ran."),
        "remediation": (
            "Re-run with options.username + options.password populated."
        ),
        "cwe": "CWE-1006",
    }


def rule_auth_failed(s):
    if not s.get("direct_syscall_winrm_auth_failed"):
        return None
    return {
        "name": "WinRM authentication failed during direct syscall probe",
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
    err = str(s.get("direct_syscall_detection_test_error") or "")
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
    err = str(s.get("direct_syscall_detection_test_error") or "")
    if not err or "pywinrm" in err:
        return None
    if "winrm: " not in err and "winrm timeout" not in err:
        return None
    return {
        "name": "WinRM connection failed during direct syscall probe",
        "severity": "INFO",
        "evidence": f"Connection error: {err}",
        "remediation": (
            "Verify WinRM is listening, the port is open, and the scanner "
            "IP is trusted."
        ),
        "cwe": "CWE-1006",
    }


DIRECT_SYSCALL_DETECTION_TEST_FINDING_RULES = [
    rule_high_direct_undetected,
    rule_positive_edr_caught,
    rule_baseline_ok_direct_failed,
    rule_baseline_failed,
    rule_creds_missing,
    rule_auth_failed,
    rule_pywinrm_missing,
    rule_connect_error,
]
