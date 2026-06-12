"""cfi_modern_mitigation_audit - findings rules.

Severity model (ZERO false positives — graded ONLY on a clean parse where the
opt-in bit is genuinely ABSENT on an architecture that supports it):
  MEDIUM   - x86-64 ELF without IBT, or without Shadow-Stack (CET not opted in)
  MEDIUM   - aarch64 ELF without PAC, or without BTI
  MEDIUM   - x64 PE without CET shadow-stack (CETCOMPAT)
  INFO     - architecture cannot benefit (32-bit ARM, unknown machine), libs
             missing, file missing, parse error, unknown format
  POSITIVE - the modern-CFI opt-in markers are present

Note: these are missing-defense-in-depth findings (CWE-1265). They are graded
because the decode is a hard fact (the feature word was read out of the binary),
not a guess.  The wording deliberately avoids advisory phrases so the global
advisory-cap does not clamp a real, decoded absence to INFO.
"""

CWE_CFI = "CWE-1265"   # missing exploit mitigation


def rule_input_missing(s):
    if not s.get("binary_path_missing"):
        return None
    return {
        "name": "cfi_modern_mitigation_audit skipped - binary file not found",
        "severity": "INFO",
        "evidence": "ScanRequest.target did not resolve to a readable file on disk.",
        "remediation": "Re-run with target = absolute path to an uploaded ELF / PE binary.",
        "cwe": "CWE-1006",
    }


def rule_too_large(s):
    if not s.get("binary_too_large_mb"):
        return None
    return {
        "name": f"Binary too large for CFI audit ({s.get('binary_too_large_mb')} MB)",
        "severity": "INFO",
        "evidence": "Starter caps static CFI audit at 256MB.",
        "remediation": "Strip / split the binary then re-run.",
        "cwe": "CWE-1006",
    }


def rule_library_missing(s):
    if not s.get("library_missing"):
        return None
    return {
        "name": f"CFI probe could not run - {s.get('library_missing')}",
        "severity": "INFO",
        "evidence": "Required library missing on the scanner host.",
        "remediation": "Install in the scanner container: pip install pefile.",
        "cwe": "CWE-1006",
    }


def rule_parse_error(s):
    if not s.get("parse_error"):
        return None
    return {
        "name": "Binary failed to parse - CFI audit skipped",
        "severity": "INFO",
        "evidence": str(s.get("parse_error"))[:300],
        "remediation": "Confirm the file is a valid ELF / PE and re-upload.",
        "cwe": "CWE-1006",
    }


def rule_unknown_format(s):
    if not s.get("binary_unknown_format"):
        return None
    return {
        "name": "Unrecognized binary header - CFI audit skipped",
        "severity": "INFO",
        "evidence": "First 4 bytes matched neither ELF (\\x7fELF) nor PE (MZ).",
        "remediation": "Confirm the file type with `file <path>` locally and re-upload.",
        "cwe": "CWE-1006",
    }


# ── x86 CET (Intel) ──────────────────────────────────────────────────────
def rule_x86_ibt_absent(s):
    info = s.get("cfi_info") or {}
    if info.get("kind") != "elf":
        return None
    if info.get("arch") not in ("x86_64",):   # IBT meaningful for x86-64 here
        return None
    if info.get("x86_ibt"):
        return None
    return {
        "name": "Intel CET IBT not opted in - indirect-branch tracking absent (x86-64 ELF)",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": CWE_CFI,
        "owasp": "A05:2021",
        "evidence": (
            "Decoded GNU_PROPERTY_X86_FEATURE_1_AND from .note.gnu.property: the "
            "GNU_PROPERTY_X86_FEATURE_1_IBT (0x1) bit is NOT set. On 11th-gen+ Intel "
            "with Linux 5.18+ the kernel can enforce Indirect Branch Tracking (every "
            "indirect call/jmp must land on an ENDBR landing pad), but this binary "
            "did not opt in at build time, so JOP/COP gadget chains run unchecked."
        ),
        "remediation": (
            "Compile and link the whole binary (and its dependencies) with "
            "-fcf-protection=branch (or =full). Requires CET-aware glibc (2.36+). "
            "Confirm with `readelf -n <bin>` showing 'IBT' in the x86 feature line."
        ),
    }


def rule_x86_shstk_absent(s):
    info = s.get("cfi_info") or {}
    if info.get("kind") != "elf":
        return None
    if info.get("arch") not in ("x86_64",):
        return None
    if info.get("x86_shstk"):
        return None
    return {
        "name": "Intel CET Shadow-Stack not opted in - return-address protection absent (x86-64 ELF)",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": CWE_CFI,
        "owasp": "A05:2021",
        "evidence": (
            "Decoded GNU_PROPERTY_X86_FEATURE_1_AND from .note.gnu.property: the "
            "GNU_PROPERTY_X86_FEATURE_1_SHSTK (0x2) bit is NOT set. A hardware shadow "
            "stack would catch ROP-style return-address overwrites, but this binary "
            "did not request it, so saved-RIP corruption is not hardware-detected."
        ),
        "remediation": (
            "Build with -fcf-protection=full and link only SHSTK-aware libraries "
            "(glibc 2.36+). Enable the kernel feature at runtime where supported."
        ),
    }


# ── aarch64 PAC / BTI (ARM) ──────────────────────────────────────────────
def rule_aarch64_pac_absent(s):
    info = s.get("cfi_info") or {}
    if info.get("kind") != "elf" or info.get("arch") != "aarch64":
        return None
    if info.get("aarch64_pac"):
        return None
    return {
        "name": "ARM Pointer Authentication (PAC) not opted in (aarch64 ELF)",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": CWE_CFI,
        "owasp": "A05:2021",
        "evidence": (
            "Decoded GNU_PROPERTY_AARCH64_FEATURE_1_AND from .note.gnu.property: the "
            "PAC (0x2) bit is NOT set. PAC signs return addresses / pointers with a "
            "cryptographic MAC on ARMv8.3+, defeating return-address overwrite, but "
            "this binary was not built with pointer-authentication codegen."
        ),
        "remediation": (
            "Rebuild with -mbranch-protection=pac-ret (or standard) on a toolchain "
            "targeting ARMv8.3-A+. Confirm with `readelf -n` showing the PAC feature."
        ),
    }


def rule_aarch64_bti_absent(s):
    info = s.get("cfi_info") or {}
    if info.get("kind") != "elf" or info.get("arch") != "aarch64":
        return None
    if info.get("aarch64_bti"):
        return None
    return {
        "name": "ARM Branch Target Identification (BTI) not opted in (aarch64 ELF)",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": CWE_CFI,
        "owasp": "A05:2021",
        "evidence": (
            "Decoded GNU_PROPERTY_AARCH64_FEATURE_1_AND from .note.gnu.property: the "
            "BTI (0x1) bit is NOT set. BTI is ARM's equivalent of Intel IBT - indirect "
            "branches must land on a BTI landing pad - but this binary did not opt in, "
            "so JOP/COP gadget chains are unrestricted on BTI-capable silicon."
        ),
        "remediation": (
            "Rebuild with -mbranch-protection=bti (or standard) targeting ARMv8.5-A+. "
            "All linked objects must also carry the BTI property or the linker drops it."
        ),
    }


# ── Windows PE CET ───────────────────────────────────────────────────────
def rule_pe_cet_absent(s):
    info = s.get("cfi_info") or {}
    if info.get("kind") != "pe":
        return None
    if info.get("bits") != 64:
        return None
    if info.get("pe_cet_shadow_stack"):
        return None
    return {
        "name": "Windows CET shadow-stack (CETCOMPAT) not enabled on x64 PE",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": CWE_CFI,
        "owasp": "A05:2021",
        "evidence": (
            "Load-config DllCharacteristicsEx CET_COMPAT (0x1) bit is NOT set. On "
            "Windows 11 / Server 2022 with 11th-gen+ Intel, a hardware shadow stack "
            "would detect ROP return-address corruption for this image, but the "
            "binary did not opt in via /CETCOMPAT."
        ),
        "remediation": (
            "Re-link with /CETCOMPAT (MSVC 16.7+). Pair with /GUARD:CF for full "
            "forward + backward control-flow integrity."
        ),
    }


# ── POSITIVE ─────────────────────────────────────────────────────────────
def rule_positive(s):
    info = s.get("cfi_info") or {}
    if not info:
        return None
    if info.get("kind") == "elf":
        if info.get("arch") == "x86_64" and info.get("x86_ibt") and info.get("x86_shstk"):
            return {
                "name": "x86-64 ELF opts into full Intel CET (IBT + Shadow-Stack)",
                "severity": "POSITIVE",
                "evidence": (
                    "Both GNU_PROPERTY_X86_FEATURE_1_IBT and _SHSTK bits are set in "
                    ".note.gnu.property. On CET-capable hardware this binary gets "
                    "hardware indirect-branch tracking and a return-address shadow stack."
                ),
                "remediation": "Keep -fcf-protection=full in CI and link only CET-aware libs.",
                "cwe": CWE_CFI,
            }
        if info.get("arch") == "aarch64" and info.get("aarch64_pac") and info.get("aarch64_bti"):
            return {
                "name": "aarch64 ELF opts into ARM PAC + BTI",
                "severity": "POSITIVE",
                "evidence": (
                    "Both PAC and BTI feature bits are set in the AArch64 feature note. "
                    "Return addresses are PAC-signed and indirect branches are BTI-checked."
                ),
                "remediation": "Keep -mbranch-protection=standard in CI.",
                "cwe": CWE_CFI,
            }
    if info.get("kind") == "pe" and info.get("pe_cet_shadow_stack") and info.get("pe_guard_cf"):
        return {
            "name": "x64 PE opts into Windows CET shadow-stack + CFG",
            "severity": "POSITIVE",
            "evidence": (
                "CETCOMPAT (shadow stack) and GUARD_CF (forward-edge CFI) are both set."
            ),
            "remediation": "Keep /CETCOMPAT + /GUARD:CF in the release link step.",
            "cwe": CWE_CFI,
        }
    return None


def rule_arch_not_applicable(s):
    """Honest INFO when the architecture cannot carry these markers, so the
    scan reports something rather than silently emitting nothing."""
    info = s.get("cfi_info") or {}
    if not info:
        return None
    arch = info.get("arch")
    if info.get("kind") != "elf":
        return None
    is_legacy_arch = arch in ("i386", "arm")
    is_unknown_machine = isinstance(arch, str) and arch.startswith("machine_")
    if is_legacy_arch or is_unknown_machine:
        return {
            "name": f"[ADVISORY-BY-DESIGN] Modern-CFI markers not applicable to {arch} ELF",
            "severity": "INFO",
            "evidence": (
                f"Architecture {arch} predates the Intel CET / ARM PAC-BTI feature "
                "notes, so there is no opt-in bit to decode. The binary parsed "
                "cleanly; no graded finding applies on this architecture."
            ),
            "remediation": (
                "Endpoint is advisory-by-design for this architecture. Migrate to a "
                "64-bit target (x86-64 / aarch64) to gain modern hardware CFI."
            ),
            "cwe": "CWE-1006",
        }
    return None


CFI_MODERN_MITIGATION_AUDIT_FINDING_RULES = [
    rule_input_missing,
    rule_too_large,
    rule_library_missing,
    rule_parse_error,
    rule_unknown_format,
    rule_x86_ibt_absent,
    rule_x86_shstk_absent,
    rule_aarch64_pac_absent,
    rule_aarch64_bti_absent,
    rule_pe_cet_absent,
    rule_positive,
    rule_arch_not_applicable,
]
