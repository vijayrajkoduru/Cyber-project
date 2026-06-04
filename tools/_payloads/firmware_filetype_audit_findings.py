"""firmware_filetype_audit - findings rules."""


def rule_library_missing(s):
    e = s.get("firmware_filetype_audit_error") or ""
    if "python-magic" not in e and "binwalk" not in e:
        return None
    return {"name": "Filetype audit dependency missing",
            "severity": "INFO",
            "evidence": e,
            "remediation": "Install via: pip install python-magic + apt install libmagic1 + binwalk.",
            "cwe": "CWE-1006"}


def rule_positive(s):
    if s.get("firmware_filetype_audit_total", 0) > 0:
        return None
    if s.get("firmware_filetype_audit_error"):
        return None
    if not s.get("firmware_total_files"):
        return None
    return {"name": f"No sensitive files in firmware extraction ({s.get('firmware_total_files', 0)} scanned)",
            "severity": "POSITIVE",
            "evidence": (f"Scanned {s.get('firmware_total_files', 0)} files, "
                         f"{s.get('firmware_unique_types', 0)} MIME types, "
                         f"{s.get('firmware_elf_count', 0)} ELFs"),
            "remediation": "Continue stripping sensitive files before firmware packaging.",
            "cwe": "CWE-200"}


def rule_notable_files(s):
    nf = s.get("firmware_notable_files") or []
    if not nf:
        return None
    sample = ", ".join(f["path"][:60] for f in nf[:5])
    return {"name": f"Sensitive files exposed in firmware ({len(nf)} files)",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-200", "owasp": "A05:2021",
            "evidence": f"Examples: {sample}",
            "remediation": ("Strip /etc/shadow, /etc/passwd, SSH host keys, .ssh/, .aws/ from "
                            "firmware before packaging. Use a build-script that excludes these "
                            "via 'find -name shadow -delete' before mksquashfs/mkfs.jffs2. "
                            "Audit your build pipeline.")}


def rule_inventory_summary(s):
    inv = s.get("firmware_type_inventory") or []
    if not inv:
        return None
    elf = s.get("firmware_elf_count", 0)
    scripts = s.get("firmware_script_count", 0)
    return {"name": f"Firmware composition: {elf} ELFs + {scripts} scripts",
            "severity": "INFO",
            "evidence": f"Top types: " + ", ".join(f"{t['mime']}({t['count']})" for t in inv[:5]),
            "remediation": ("Use this inventory to prioritize next audit: ELFs -> Binary Exploitation "
                            "module (BOF); scripts -> grep for hardcoded creds + dangerous fork/exec; "
                            "JSON/YAML configs -> grep for keys/URLs."),
            "cwe": "CWE-200"}


FIRMWARE_FILETYPE_AUDIT_FINDING_RULES = [rule_library_missing, rule_positive,
                                            rule_notable_files, rule_inventory_summary]
