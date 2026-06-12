"""cpio_archive_extract - findings rules.

ZERO-FP contract: graded severity only when the sensitive artefact was
actually extracted from the customer's firmware. Detection-without-tool and
'no cpio present' are INFO only.
"""


def rule_not_present(s):
    if s.get("cpio_present"):
        return None
    if s.get("cpio_archive_extract_total") is None:
        return None
    return {"name": "No cpio archive detected in firmware",
            "severity": "INFO",
            "evidence": "No newc/crc/odc or binary cpio magic found in first 96 MB",
            "remediation": ("This firmware does not embed a cpio/initramfs root filesystem. "
                            "Its root FS is likely squashfs / JFFS2 / UBIFS — see the binwalk "
                            "and squashfs scanners for those."),
            "cwe": "CWE-200"}


def rule_tool_missing(s):
    if not s.get("cpio_tool_missing"):
        return None
    return {"name": "cpio archive detected but `cpio` extractor not installed",
            "severity": "INFO",
            "evidence": (f"cpio magic {s.get('cpio_magic')} @ offset {s.get('cpio_offset')} "
                         f"— extraction skipped (cpio binary absent on scanner host)"),
            "remediation": ("A cpio archive is present. Install GNU cpio (apt-get install cpio) "
                            "on the scanner host to enable filesystem extraction + sensitive-file "
                            "auditing, or extract manually with `cpio -idmv < archive.cpio`."),
            "cwe": "CWE-1006"}


def rule_positive(s):
    if not s.get("cpio_present"):
        return None
    if s.get("cpio_tool_missing"):
        return None
    if s.get("cpio_extracted_files") is None:
        return None
    if s.get("cpio_sensitive_hits"):
        return None
    return {"name": f"cpio root filesystem extracted cleanly ({s.get('cpio_extracted_files', 0)} files)",
            "severity": "POSITIVE",
            "evidence": (f"cpio @ offset {s.get('cpio_offset')}, "
                         f"{s.get('cpio_extracted_files', 0)} files, "
                         f"{s.get('cpio_extracted_size', 0)} bytes — no plaintext creds/keys found"),
            "remediation": "Continue stripping credentials + private keys before packaging the initramfs.",
            "cwe": "CWE-200"}


def rule_sensitive_artefacts(s):
    hits = s.get("cpio_sensitive_hits") or []
    if not hits:
        return None
    keys = [h for h in hits if h.get("kind") in ("openssh-private-key", "telnetd-backdoor-snippet")]
    sample = ", ".join(f"{h['path']}({h['kind']})" for h in hits[:5])
    sev = "HIGH" if keys else "MEDIUM"
    cvss = "7.5" if keys else "5.3"
    return {"name": f"Sensitive artefacts in cpio filesystem ({len(hits)} items)",
            "severity": sev, "cvss": cvss,
            "cwe": "CWE-798", "owasp": "A07:2021",
            "evidence": f"Examples: {sample}",
            "remediation": ("Plaintext credentials, private keys, or telnetd backdoor stanzas were "
                            "extracted from the firmware's cpio root filesystem. Remove /etc/shadow, "
                            "/etc/passwd hashes, SSH host/identity keys, and hardcoded telnetd shells "
                            "from the build before packaging. Rotate any leaked key material — once a "
                            "firmware image ships, embedded secrets are world-readable.")}


CPIO_ARCHIVE_EXTRACT_FINDING_RULES = [rule_not_present, rule_tool_missing,
                                       rule_positive, rule_sensitive_artefacts]
