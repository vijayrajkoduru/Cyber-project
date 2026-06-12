"""elf_section_security_audit - findings rules.

ZERO-FP contract: a graded finding fires only when at least one ELF was
actually parsed and the missing mitigation was confirmed from its headers.
Missing-mitigation findings are deliberately graded LOW/MEDIUM (a hardening
gap is a real, confirmed condition — but not a demonstrated exploit), with
executable-stack at MEDIUM since it directly enables shellcode on overflow.
"""


def rule_no_elf(s):
    if s.get("elf_count") != 0:
        return None
    if "elf_count" not in s:
        return None
    return {"name": "No parseable ELF binaries in firmware",
            "severity": "INFO",
            "evidence": "binwalk extraction (or bare-ELF fallback) yielded no ELF binaries",
            "remediation": ("Either the firmware contains no ELF executables (pure config / "
                            "scripted image) or extraction did not surface them. If you expected "
                            "binaries, confirm the binwalk/squashfs extraction step succeeded."),
            "cwe": "CWE-200"}


def rule_exec_stack(s):
    bins = s.get("elf_exec_stack") or []
    if not bins:
        return None
    return {"name": f"{len(bins)} firmware binary/binaries ship with an executable stack",
            "severity": "MEDIUM", "cvss": "5.9",
            "cwe": "CWE-119", "owasp": "A06:2021",
            "evidence": f"PT_GNU_STACK has PF_X set on: {', '.join(bins[:6])}",
            "remediation": ("These binaries have a writable + executable stack (NX/DEP disabled), "
                            "so a stack buffer overflow can run injected shellcode directly. "
                            "Rebuild with a modern toolchain (GCC/Clang mark the stack non-exec by "
                            "default); remove any explicit `-z execstack` and audit inline asm that "
                            "requests an executable stack.")}


def rule_no_relro(s):
    bins = s.get("elf_no_relro") or []
    if not bins:
        return None
    return {"name": f"{len(bins)} firmware binary/binaries built without RELRO",
            "severity": "LOW", "cvss": "3.3",
            "cwe": "CWE-119", "owasp": "A06:2021",
            "evidence": f"No PT_GNU_RELRO segment on: {', '.join(bins[:6])}",
            "remediation": ("Without RELRO the GOT/PLT stays writable, easing GOT-overwrite "
                            "exploitation after a memory-corruption bug. Rebuild with "
                            "`-Wl,-z,relro,-z,now` for full RELRO.")}


def rule_no_pie(s):
    bins = s.get("elf_no_pie") or []
    if not bins:
        return None
    return {"name": f"{len(bins)} firmware binary/binaries built without PIE (no ASLR for code)",
            "severity": "LOW", "cvss": "3.3",
            "cwe": "CWE-119", "owasp": "A06:2021",
            "evidence": f"ET_EXEC (non-PIE) type on: {', '.join(bins[:6])}",
            "remediation": ("Non-PIE executables load at a fixed base, defeating ASLR for the main "
                            "image and simplifying ROP. Rebuild with `-fPIE -pie`. On constrained "
                            "MMU-less targets PIE may be impractical — document the exception.")}


def rule_no_canary(s):
    bins = s.get("elf_no_canary") or []
    if not bins:
        return None
    return {"name": f"{len(bins)} firmware binary/binaries built without stack canaries",
            "severity": "LOW", "cvss": "3.3",
            "cwe": "CWE-121", "owasp": "A06:2021",
            "evidence": f"No __stack_chk_fail reference in: {', '.join(bins[:6])}",
            "remediation": ("No stack-smashing protector means classic stack overflows overwrite "
                            "the return address undetected. Rebuild with `-fstack-protector-strong`. "
                            "(Heuristic: based on absence of the __stack_chk_fail symbol.)")}


def rule_inventory(s):
    inv = s.get("elf_inventory") or []
    if not inv:
        return None
    # Suppress the inventory INFO if nothing else fired AND everything is clean,
    # so we still record that binaries were audited.
    hardened = sum(1 for e in inv if e.get("nx") and e.get("relro") and e.get("canary"))
    return {"name": f"ELF hardening inventory: {len(inv)} binaries audited",
            "severity": "INFO",
            "evidence": (f"{hardened}/{len(inv)} fully hardened (NX+RELRO+canary); "
                         f"mode={s.get('elf_mode')}"),
            "remediation": ("Per-binary mitigation posture is tabulated in the intel section. Track "
                            "the weakest binaries (network-facing daemons first) for toolchain "
                            "hardening in the next firmware build."),
            "cwe": "CWE-200"}


ELF_SECTION_SECURITY_AUDIT_FINDING_RULES = [rule_no_elf, rule_exec_stack, rule_no_relro,
                                             rule_no_pie, rule_no_canary, rule_inventory]
