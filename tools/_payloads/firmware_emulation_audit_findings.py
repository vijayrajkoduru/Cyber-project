"""firmware_emulation_audit - findings rules."""


def rule_qemu_missing(s):
    if s.get("firmware_emulation_audit_error") != "qemu-user-static not installed":
        return None
    return {"name": "qemu-user-static not installed",
            "severity": "INFO",
            "evidence": "shutil.which('qemu-arm-static'/'qemu-aarch64-static'/'qemu-mipsel-static') all None",
            "remediation": "Install: apt-get install qemu-user-static.",
            "cwe": "CWE-1006"}


def rule_no_arm_binaries(s):
    if not s.get("firmware_no_arm_binaries"):
        return None
    return {"name": "No ARM/MIPS binaries detected in firmware extraction",
            "severity": "INFO",
            "evidence": "ELF e_machine field did not match arm/aarch64/mipsel/mips on any extracted file",
            "remediation": ("This firmware appears to be x86 / non-ARM. Use BOF module (#7) "
                            "for x86-64 binary analysis instead. If you expected ARM, verify "
                            "binwalk extraction succeeded."),
            "cwe": "CWE-1006"}


def rule_positive(s):
    if s.get("firmware_emulation_audit_total", 0) > 0:
        return None
    if s.get("firmware_emulation_audit_error"):
        return None
    if not s.get("firmware_binaries_tested"):
        return None
    return {"name": f"All {s.get('firmware_binaries_tested', 0)} binaries booted cleanly under qemu",
            "severity": "POSITIVE",
            "evidence": "No crashes during --help/--version invocation",
            "remediation": "Continue testing under fuzz harness (AFL++ qemu mode).",
            "cwe": "CWE-1006"}


def rule_crashes(s):
    crashed = s.get("firmware_emulation_crashed") or []
    if not crashed:
        return None
    return {"name": f"{len(crashed)} firmware binary/binaries SEGFAULT on --help",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-617", "owasp": "A06:2021",
            "evidence": f"Crashed: {', '.join(crashed[:5])}",
            "remediation": ("Each segfault is a potential memory-corruption bug. Triage with gdb-"
                            "multiarch + qemu-user (set QEMU_GDB=1234) to capture stack trace. "
                            "If reachable from network input, this is a remote code-execution "
                            "candidate. Patch with bounds checks + bounds-aware libc replacements.")}


def rule_banners(s):
    banners = s.get("firmware_emulation_banners") or []
    if not banners:
        return None
    return {"name": f"Firmware binary banners captured ({len(banners)} entries)",
            "severity": "INFO",
            "evidence": "Banners reveal version strings useful for CVE matching",
            "remediation": ("Cross-reference each banner against NVD CVE DB (use System Exploit "
                            "module #10 with the captured version string). Embedded daemons "
                            "frequently expose telnetd, dropbear, busybox versions with known CVEs."),
            "cwe": "CWE-200"}


FIRMWARE_EMULATION_AUDIT_FINDING_RULES = [rule_qemu_missing, rule_no_arm_binaries,
                                            rule_positive, rule_crashes, rule_banners]
