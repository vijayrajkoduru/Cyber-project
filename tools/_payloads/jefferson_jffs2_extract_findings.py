"""jefferson_jffs2_extract - findings rules."""


def rule_positive(s):
    if s.get("jefferson_jffs2_extract_total"):
        return None
    if s.get("jefferson_jffs2_extract_error"):
        return None
    if s.get("jffs2_present"):
        return None
    return {"name": "No JFFS2 filesystem present in firmware",
            "severity": "POSITIVE",
            "evidence": "JFFS2 magic (0x1985 / 0x8519) not found in first 64 MB",
            "remediation": ("Either firmware uses a different filesystem (squashfs/ubifs/cramfs) "
                            "or is fully encrypted. No JFFS2-specific risk applies."),
            "cwe": "CWE-200", "owasp": "A05:2021"}


def rule_jffs2_extracted(s):
    files = s.get("jffs2_extracted_files", 0)
    if not files:
        return None
    size = s.get("jffs2_extracted_size", 0)
    offset = s.get("jffs2_offset", 0)
    size_mb = round(size / (1024 * 1024), 2)
    return {"name": f"JFFS2 filesystem fully extractable ({files} files, {size_mb} MB)",
            "severity": "INFO",
            "evidence": f"jefferson extracted {files} files starting at offset 0x{offset:x}",
            "remediation": ("JFFS2 root filesystem is reachable for offline analysis. Vendor "
                            "should consider switching to signed UBIFS images or encrypting "
                            "the JFFS2 partition with dm-crypt. Modern fleets prefer SquashFS+ "
                            "OverlayFS with kernel-mode dm-verity integrity guards (NIST SP "
                            "800-193 §4.3 platform integrity)."),
            "cwe": "CWE-200", "owasp": "A05:2021"}


def rule_jffs2_sensitive_artefacts(s):
    items = s.get("jffs2_sensitive_hits") or []
    if not items:
        return None
    pw_kinds = [h for h in items if h.get("kind") in ("openssh-private-key", "password-hash",
                                                      "telnetd-backdoor-snippet")]
    if pw_kinds:
        sev, cvss = "HIGH", "8.1"
        title = (f"Plaintext credentials / backdoors in JFFS2 "
                 f"({len(pw_kinds)} matches)")
    else:
        sev, cvss = "MEDIUM", "5.5"
        title = f"Sensitive files inside JFFS2 filesystem ({len(items)} matches)"
    sample = ", ".join(f"{h.get('kind', '?')}@{h.get('path', '')[:50]}"
                       for h in items[:5])
    return {"name": title,
            "severity": sev, "cvss": cvss,
            "cwe": "CWE-798", "owasp": "A07:2021",
            "evidence": f"Examples: {sample}",
            "remediation": ("Strip /etc/shadow, /etc/passwd hashes, /root/.ssh/, "
                            "/lib/firmware/*key* from production JFFS2 builds. If host SSH "
                            "keys are required, generate them on first boot. Telnetd hardcoded "
                            "passwords MUST be removed — disable telnet entirely (CWE-798, "
                            "ETSI EN 303 645 §5.1-1).")}


JEFFERSON_JFFS2_EXTRACT_FINDING_RULES = [rule_positive, rule_jffs2_extracted,
                                           rule_jffs2_sensitive_artefacts]
