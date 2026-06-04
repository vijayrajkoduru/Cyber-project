"""encoded_shellcode_detection_test - findings rules.

Severity model (FLIPPED vs. normal convention):

  HIGH      The 256-byte base64-encoded benign shellcode was DECODED on
            the target without AV blocking the static-scan layer. This
            means the customer's AV/EDR doesn't catch the textbook
            base64 shellcode pattern in transit (in WinRM PS scriptblock)
            or in PowerShell's AMSI hook. Attackers using msfvenom +
            base64 stager will get past static detection.
  POSITIVE  AV caught the decode at the static-scan layer (best case).
  INFO      Could not run.

Note: Because the shellcode is provably inert (253 NOPs + xor eax,eax +
ret) and is never executed, this is purely a detection-capability
measurement, not a vulnerability.
"""


def rule_high_decode_undetected(s):
    if s.get("encoded_shellcode_blocked"):
        return None
    if not s.get("encoded_shellcode_decode_ok"):
        return None
    if (s.get("encoded_shellcode_decoded_len") or 0) != 256:
        return None
    return {
        "name": "Base64-encoded shellcode decoded on Windows host without AV detection",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-693",
        "owasp": "A05:2021",
        "mitre": "T1027.013",
        "evidence": (
            f"256-byte benign shellcode (253 NOPs + xor eax,eax + ret) "
            f"was base64-encoded ({s.get('encoded_shellcode_b64_chars') or 0} "
            f"chars) and submitted to the target via WinRM PowerShell. "
            f"The decoded byte array's first byte = "
            f"{s.get('encoded_shellcode_first_byte') or '?'} (expected 0x90 "
            f"= NOP), confirming the buffer reached memory intact. AV/EDR "
            f"did NOT block the decode at the static-scan / AMSI layer. "
            "Attackers using msfvenom-shikata-ga-nai + base64 stagers will "
            "bypass this control."
        ),
        "remediation": (
            "1. Enable PowerShell Constrained Language Mode for non-admin "
            "users (`$env:__PSLockdownPolicy='4'`) so [Convert]::FromBase64String "
            "of binary blobs is heavily restricted. 2. Enable PowerShell "
            "Script Block Logging (Event ID 4104) and forward to SIEM with "
            "a regex rule on long base64 strings (>200 chars) inside "
            "[byte[]] casts. 3. Tune AV to scan PowerShell AMSI buffers in "
            "real-time (Defender: `Set-MpPreference -DisableScriptScanning "
            "$false`). 4. If the customer uses CrowdStrike Falcon, enable "
            "the 'Suspicious PowerShell Pattern' detection in policy. "
            "5. Re-run this probe after each fix - blocking should occur "
            "before the LEN= marker is printed."
        ),
    }


def rule_positive_av_caught(s):
    if not s.get("encoded_shellcode_blocked"):
        return None
    return {
        "name": "AV caught base64 shellcode decode at static-scan layer",
        "severity": "POSITIVE",
        "evidence": (
            "Submitting a 256-byte benign shellcode (NOP sled + xor/ret) "
            "as a base64 blob to PowerShell on the target was blocked by "
            "AV / Defender / EDR. The decode primitive never returned the "
            "LEN= marker. The customer's static-scan / AMSI hook is "
            "catching the canonical msfvenom-style stager pattern."
        ),
        "remediation": (
            "1. Schedule a weekly automated run of this probe to catch "
            "regression. 2. Forward AV block events (Defender Event ID "
            "1116 / 1117) to SIEM. 3. Consider rotating different "
            "shellcode patterns through this probe (custom encoder, RC4, "
            "AES) to test the full decoder-detection ruleset over time."
        ),
        "cwe": "CWE-693",
        "owasp": "A05:2021",
        "mitre": "T1027.013",
    }


def rule_partial(s):
    if s.get("encoded_shellcode_blocked"):
        return None
    if s.get("encoded_shellcode_decode_ok"):
        return None
    if s.get("encoded_shellcode_creds_missing"):
        return None
    if s.get("encoded_shellcode_winrm_auth_failed"):
        return None
    if s.get("encoded_shellcode_detection_test_error"):
        return None
    return {
        "name": "Encoded-shellcode probe did not complete cleanly",
        "severity": "INFO",
        "evidence": (
            "Neither a clean decode marker (DECODE-OK-NOT-EXECUTED) nor a "
            "recognised AV-block signature was observed. Summary: "
            + str(s.get("encoded_shellcode_summary") or "")[:300]
        ),
        "remediation": (
            "Re-run; check whether Constrained Language Mode is forced on "
            "the audit account (which silently blocks [Convert] / [byte[]] "
            "casts without producing the expected AV signature)."
        ),
        "cwe": "CWE-693",
    }


def rule_creds_missing(s):
    if not s.get("encoded_shellcode_creds_missing"):
        return None
    return {
        "name": "Encoded-shellcode detection probe skipped - WinRM credentials missing",
        "severity": "INFO",
        "evidence": ("This probe requires options.username + options.password. "
                     "Without creds no test ran."),
        "remediation": (
            "Re-run with options.username + options.password populated."
        ),
        "cwe": "CWE-1006",
    }


def rule_auth_failed(s):
    if not s.get("encoded_shellcode_winrm_auth_failed"):
        return None
    return {
        "name": "WinRM authentication failed during encoded-shellcode probe",
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
    err = str(s.get("encoded_shellcode_detection_test_error") or "")
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
    err = str(s.get("encoded_shellcode_detection_test_error") or "")
    if not err or "pywinrm" in err:
        return None
    if "winrm: " not in err and "winrm timeout" not in err:
        return None
    return {
        "name": "WinRM connection failed during encoded-shellcode probe",
        "severity": "INFO",
        "evidence": f"Connection error: {err}",
        "remediation": (
            "Verify WinRM is listening, the port is open, and the scanner "
            "IP is trusted."
        ),
        "cwe": "CWE-1006",
    }


ENCODED_SHELLCODE_DETECTION_TEST_FINDING_RULES = [
    rule_high_decode_undetected,
    rule_positive_av_caught,
    rule_partial,
    rule_creds_missing,
    rule_auth_failed,
    rule_pywinrm_missing,
    rule_connect_error,
]
