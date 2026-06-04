"""binwalk_signature_scan - findings rules."""


def rule_positive(s):
    if s.get("binwalk_signature_scan_total"):
        return None
    if s.get("binwalk_signature_scan_error"):
        return None
    if s.get("binwalk_extracted_files"):
        return None
    return {"name": "binwalk found no extractable filesystem signatures",
            "severity": "POSITIVE",
            "evidence": "Signature scan + extract pass produced no embedded filesystems",
            "remediation": ("Either firmware is heavily packed/encrypted (good) or this binary "
                            "is not a firmware blob. Verify with `binwalk -A` opcodes scan."),
            "cwe": "CWE-200", "owasp": "A05:2021"}


def rule_filesystems_detected(s):
    fs = s.get("binwalk_detected_fs") or []
    if not fs:
        return None
    return {"name": f"Embedded filesystem(s) detected: {', '.join(fs[:6])}",
            "severity": "INFO",
            "evidence": f"binwalk signature scan found: {', '.join(fs)}",
            "remediation": ("Filesystem extraction is now possible — proceed with downstream "
                            "static analysis (strings, hardcoded creds, CVE matching). "
                            "Vendor should ship encrypted/signed firmware images per NIST "
                            "SP 800-193 Platform Firmware Resiliency."),
            "cwe": "CWE-200", "owasp": "A05:2021"}


def rule_extraction_succeeded(s):
    if not s.get("binwalk_extracted_files"):
        return None
    files = s.get("binwalk_extracted_files", 0)
    size = s.get("binwalk_extracted_size", 0)
    size_mb = round(size / (1024 * 1024), 2)
    return {"name": f"Firmware contents fully extractable ({files} files, {size_mb} MB)",
            "severity": "INFO",
            "evidence": f"binwalk -e succeeded; {files} files extracted totalling {size_mb} MB",
            "remediation": ("Firmware unpacked without keys — root filesystem is reachable. "
                            "Consider signing + encrypting the firmware image (vendor-side fix); "
                            "until then, attackers can extract and audit the same image trivially."),
            "cwe": "CWE-200", "owasp": "A05:2021"}


def rule_sensitive_files_found(s):
    hits = s.get("binwalk_sensitive_hits") or []
    if not hits:
        return None
    pw_kinds = [h for h in hits if h.get("kind") in ("openssh-private-key", "password-hash")]
    if pw_kinds:
        sev, cvss = "HIGH", "8.1"
        title = (f"Plaintext credential material in firmware "
                 f"({len(pw_kinds)} keys/hashes inside extracted FS)")
    else:
        sev, cvss = "MEDIUM", "5.5"
        title = f"Sensitive filenames present in extracted firmware ({len(hits)} matches)"
    sample = ", ".join(h.get("path", "")[:60] for h in hits[:5])
    return {"name": title,
            "severity": sev, "cvss": cvss,
            "cwe": "CWE-798", "owasp": "A07:2021",
            "evidence": f"Examples: {sample}",
            "remediation": ("Strip /etc/shadow, /etc/passwd hashes, SSH host keys, and any "
                            ".ssh/ contents from production firmware. If host keys are required, "
                            "generate them on first boot via /etc/init.d/regen-ssh-keys. Never "
                            "ship the same private key across an entire device fleet.")}


BINWALK_SIGNATURE_SCAN_FINDING_RULES = [rule_positive, rule_filesystems_detected,
                                          rule_extraction_succeeded, rule_sensitive_files_found]
