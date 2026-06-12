"""aslr_textrel_audit - findings rules.

Severity model (ZERO false positives — graded ONLY on a decoded fact):
  HIGH     - ELF DT_TEXTREL present (writable .text relocations break W^X + ASLR)
  HIGH     - PE DYNAMICBASE set BUT RELOCS_STRIPPED (loader silently fixes base)
  HIGH     - ELF non-PIE executable (fixed .text base, ret2text without leak)
  HIGH     - PE DYNAMICBASE absent (fixed ImageBase)
  MEDIUM   - PE64 DYNAMICBASE on but HIGH_ENTROPY_VA off (24-bit ASLR brute-forceable)
  INFO     - libs missing / file missing / parse error / unknown format
  POSITIVE - PIE + no TEXTREL (ELF) / DYNAMICBASE + HIGH_ENTROPY + relocs intact (PE)
"""

CWE_ASLR = "CWE-1265"   # missing exploit mitigation
CWE_TEXTREL = "CWE-266"  # incorrect privilege (W^X violation family)


def rule_input_missing(s):
    if not s.get("binary_path_missing"):
        return None
    return {
        "name": "aslr_textrel_audit skipped - binary file not found",
        "severity": "INFO",
        "evidence": "ScanRequest.target did not resolve to a readable file on disk.",
        "remediation": "Re-run with target = absolute path to an uploaded ELF / PE binary.",
        "cwe": "CWE-1006",
    }


def rule_too_large(s):
    if not s.get("binary_too_large_mb"):
        return None
    return {
        "name": f"Binary too large for ASLR audit ({s.get('binary_too_large_mb')} MB)",
        "severity": "INFO",
        "evidence": "Starter caps static ASLR audit at 256MB.",
        "remediation": "Strip / split the binary then re-run.",
        "cwe": "CWE-1006",
    }


def rule_library_missing(s):
    if not s.get("library_missing"):
        return None
    return {
        "name": f"ASLR probe could not run - {s.get('library_missing')}",
        "severity": "INFO",
        "evidence": "Required library missing on the scanner host.",
        "remediation": "Install in the scanner container: pip install pwntools pefile.",
        "cwe": "CWE-1006",
    }


def rule_parse_error(s):
    if not s.get("parse_error"):
        return None
    return {
        "name": "Binary failed to parse - ASLR audit skipped",
        "severity": "INFO",
        "evidence": str(s.get("parse_error"))[:300],
        "remediation": "Confirm the file is a valid ELF / PE and re-upload.",
        "cwe": "CWE-1006",
    }


def rule_unknown_format(s):
    if not s.get("binary_unknown_format"):
        return None
    return {
        "name": "Unrecognized binary header - ASLR audit skipped",
        "severity": "INFO",
        "evidence": "First 4 bytes matched neither ELF (\\x7fELF) nor PE (MZ).",
        "remediation": "Confirm the file type with `file <path>` locally and re-upload.",
        "cwe": "CWE-1006",
    }


def rule_elf_textrel(s):
    info = s.get("aslr_info") or {}
    if info.get("kind") != "elf" or not info.get("textrel"):
        return None
    return {
        "name": "ELF text relocations present (DT_TEXTREL) - W^X and ASLR both broken",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": CWE_TEXTREL,
        "owasp": "A05:2021",
        "evidence": (
            "Decoded DT_TEXTREL / DF_TEXTREL from the PT_DYNAMIC array. The dynamic "
            "linker must make the .text segment writable to apply relocations, which "
            "violates W^X (executable + writable code pages) and forces the segment to "
            "a fixed mapping that defeats full ASLR on the code."
        ),
        "remediation": (
            "Rebuild all objects as position-independent code (-fPIC) so no text "
            "relocations are emitted. Confirm with `readelf -d <bin> | grep TEXTREL` "
            "showing no entry, and `scanelf -qT <bin>` reporting clean."
        ),
    }


def rule_elf_no_pie(s):
    info = s.get("aslr_info") or {}
    if info.get("kind") != "elf" or info.get("static"):
        return None
    if info.get("pie"):
        return None
    return {
        "name": "ELF executable is non-PIE - code segment loads at a fixed address",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": CWE_ASLR,
        "owasp": "A05:2021",
        "evidence": (
            "The binary is not position-independent (no ET_DYN + PT_INTERP + PIE "
            "marker). Even with kernel ASLR on, .text maps to the same address each "
            "run, so ret2text / ret2plt gadget chains are reachable with no leak."
        ),
        "remediation": (
            "Compile and link with -fPIE -pie. Most modern distros default to PIE; "
            "drop any -no-pie / -fno-PIE override in the build flags."
        ),
    }


def rule_pe_no_dynamicbase(s):
    info = s.get("aslr_info") or {}
    if info.get("kind") != "pe" or info.get("dynamicbase"):
        return None
    return {
        "name": "PE ASLR disabled - DYNAMICBASE bit absent (fixed ImageBase)",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": CWE_ASLR,
        "owasp": "A05:2021",
        "evidence": (
            "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040) is NOT set; the loader "
            "places this image at its preferred ImageBase on every run, so module "
            "addresses are predictable for ret2 / ROP without a leak."
        ),
        "remediation": "Re-link with /DYNAMICBASE (MSVC: Randomized Base Address = Yes).",
    }


def rule_pe_relocs_stripped(s):
    info = s.get("aslr_info") or {}
    if info.get("kind") != "pe":
        return None
    if not (info.get("dynamicbase") and info.get("relocs_stripped")):
        return None
    return {
        "name": "PE DYNAMICBASE set but relocations stripped - ASLR silently disabled",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": CWE_ASLR,
        "owasp": "A05:2021",
        "evidence": (
            "DYNAMICBASE is requested yet IMAGE_FILE_RELOCS_STRIPPED (0x0001) is set "
            "in the file header. The Windows loader cannot relocate an image with no "
            "relocation table, so it loads at the fixed ImageBase and ASLR does NOT "
            "apply - a contradiction that produces a false sense of protection."
        ),
        "remediation": (
            "Re-link without /FIXED (the linker emits /FIXED:NO by default for EXEs "
            "when /DYNAMICBASE is on). Confirm the .reloc section is present with "
            "`dumpbin /headers <bin>`."
        ),
    }


def rule_pe_no_high_entropy(s):
    info = s.get("aslr_info") or {}
    if info.get("kind") != "pe" or info.get("bits") != 64:
        return None
    if not info.get("dynamicbase"):
        return None    # already HIGH via rule_pe_no_dynamicbase
    if info.get("high_entropy_va"):
        return None
    return {
        "name": "PE64 ASLR limited to 32-bit space - HIGH_ENTROPY_VA absent",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": CWE_ASLR,
        "evidence": (
            "64-bit PE with DYNAMICBASE but no HIGH_ENTROPY_VA (0x0020). The image "
            "gets only ~24 bits of randomization, which is brute-forceable from a "
            "remote service over thousands of requests."
        ),
        "remediation": "Re-link with /HIGHENTROPYVA (default for VS2019+).",
    }


def rule_positive(s):
    info = s.get("aslr_info") or {}
    if not info:
        return None
    if info.get("kind") == "elf" and not info.get("static"):
        if info.get("pie") and not info.get("textrel"):
            return {
                "name": "ELF is PIE with no text relocations - ASLR fully effective",
                "severity": "POSITIVE",
                "evidence": (
                    "Position-independent (PIE) and no DT_TEXTREL. .text maps to a "
                    "random base every run; exploitation needs an address-leak primitive."
                ),
                "remediation": "Keep -fPIE -pie + -fPIC in CI; add full RELRO and CET next.",
                "cwe": CWE_ASLR,
            }
    if info.get("kind") == "pe":
        if info.get("dynamicbase") and not info.get("relocs_stripped") and \
           (info.get("bits") != 64 or info.get("high_entropy_va")):
            return {
                "name": "PE has working ASLR (DYNAMICBASE + relocations + high-entropy)",
                "severity": "POSITIVE",
                "evidence": (
                    "DYNAMICBASE is set, the relocation table is intact, and (for "
                    "64-bit) HIGH_ENTROPY_VA is on - ASLR is genuinely active."
                ),
                "remediation": "Keep /DYNAMICBASE /HIGHENTROPYVA in CI; add /CETCOMPAT next.",
                "cwe": CWE_ASLR,
            }
    return None


ASLR_TEXTREL_AUDIT_FINDING_RULES = [
    rule_input_missing,
    rule_too_large,
    rule_library_missing,
    rule_parse_error,
    rule_unknown_format,
    rule_elf_textrel,
    rule_elf_no_pie,
    rule_pe_no_dynamicbase,
    rule_pe_relocs_stripped,
    rule_pe_no_high_entropy,
    rule_positive,
]
