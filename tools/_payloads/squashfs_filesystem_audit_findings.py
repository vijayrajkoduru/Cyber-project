"""squashfs_filesystem_audit - findings rules.

ZERO-FP contract: graded severity only when sensitive content was actually
extracted from the customer's SquashFS root filesystem. Detection-only and
missing-tool cases are INFO.
"""


def rule_not_present(s):
    if s.get("squashfs_present"):
        return None
    if s.get("squashfs_filesystem_audit_total") is None:
        return None
    return {"name": "No SquashFS filesystem detected in firmware",
            "severity": "INFO",
            "evidence": "No hsqs/sqsh superblock magic found in first 96 MB",
            "remediation": ("This firmware does not embed a SquashFS root filesystem. Check the "
                            "cpio / JFFS2 / binwalk scanners for other filesystem types."),
            "cwe": "CWE-200"}


def rule_tool_missing(s):
    if not s.get("squashfs_tool_missing"):
        return None
    return {"name": f"SquashFS detected ({s.get('squashfs_compression')}) but unsquashfs not installed",
            "severity": "INFO",
            "evidence": (f"SquashFS v{s.get('squashfs_version')} ({s.get('squashfs_compression')} "
                         f"compression, {s.get('squashfs_endian')}-endian) @ offset "
                         f"{s.get('squashfs_offset')} — extraction skipped (unsquashfs absent)"),
            "remediation": ("Install squashfs-tools (apt-get install squashfs-tools) on the scanner "
                            "host to enable root-filesystem extraction + sensitive-file auditing, or "
                            "extract manually with `unsquashfs rootfs.squashfs`."),
            "cwe": "CWE-1006"}


def rule_version_info(s):
    # Detection succeeded + extraction ran but produced a clean result OR
    # is reported alongside the positive; emit an INFO inventory line so the
    # PDF records the FS version/compression. Only fires when we extracted.
    if not s.get("squashfs_present"):
        return None
    if s.get("squashfs_tool_missing"):
        return None
    if s.get("squashfs_extracted_files") is None:
        return None
    return {"name": f"SquashFS v{s.get('squashfs_version')} root filesystem inventory",
            "severity": "INFO",
            "evidence": (f"version={s.get('squashfs_version')}, "
                         f"compression={s.get('squashfs_compression')}, "
                         f"{s.get('squashfs_extracted_files', 0)} files, "
                         f"{s.get('squashfs_extracted_size', 0)} bytes extracted"),
            "remediation": ("Use this filesystem inventory to prioritise auditing: enumerate the "
                            "extracted /etc, /usr/bin and /www trees for hardcoded creds, world-"
                            "writable setuid binaries, and outdated daemon versions (busybox/"
                            "dropbear/lighttpd)."),
            "cwe": "CWE-200"}


def rule_sensitive_artefacts(s):
    hits = s.get("squashfs_sensitive_hits") or []
    if not hits:
        return None
    keys = [h for h in hits if h.get("kind") in ("openssh-private-key", "telnetd-backdoor-snippet")]
    sample = ", ".join(f"{h['path']}({h['kind']})" for h in hits[:5])
    sev = "HIGH" if keys else "MEDIUM"
    cvss = "7.5" if keys else "5.3"
    return {"name": f"Sensitive artefacts in SquashFS root filesystem ({len(hits)} items)",
            "severity": sev, "cvss": cvss,
            "cwe": "CWE-798", "owasp": "A07:2021",
            "evidence": f"Examples: {sample}",
            "remediation": ("Plaintext credentials, private keys, or telnetd backdoor stanzas were "
                            "extracted from the firmware's SquashFS root filesystem. Strip /etc/"
                            "shadow, SSH host/identity keys, wpa_supplicant secrets, and hardcoded "
                            "telnetd shells from the build pipeline before mksquashfs. Rotate every "
                            "leaked key — shipped firmware secrets are recoverable by anyone holding "
                            "the image.")}


SQUASHFS_FILESYSTEM_AUDIT_FINDING_RULES = [rule_not_present, rule_tool_missing,
                                            rule_version_info, rule_sensitive_artefacts]
