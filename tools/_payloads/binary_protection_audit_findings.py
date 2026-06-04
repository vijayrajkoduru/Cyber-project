"""binary_protection_audit - findings rules.

Severity model:
  CRITICAL - NX/DEP disabled (stack is executable -> classic shellcode-on-stack)
  HIGH     - PIE/ASLR disabled, RELRO=none, Stack Canary disabled, CFG disabled
  MEDIUM   - RELRO=partial, FORTIFY_SOURCE absent, CET-IBT absent, no high-entropy ASLR
  INFO     - probe missing pwntools/pefile, Mach-O / unknown format, file not found
  POSITIVE - all mitigations present and modern (RELRO=full + PIE + NX + Canary + Fortify)
"""


def _missing(p: dict, key: str) -> bool:
    """True iff p[key] is explicitly False (not None / missing key)."""
    return p.get(key) is False


def rule_input_missing(s):
    if not s.get("binary_path_missing"):
        return None
    return {
        "name": "binary_protection_audit skipped - binary file not found at target path",
        "severity": "INFO",
        "evidence": (
            f"ScanRequest.target={s.get('binary_path') or '?'} did not resolve to a "
            "readable file on disk.  Customer must upload the binary first; the path "
            "supplied is what the scanner attempted to open."
        ),
        "remediation": (
            "Re-run with target = absolute path to an ELF / PE binary.  In the VulnusLab "
            "dashboard, the file-upload widget stores binaries under /tmp/vl_uploads/."
        ),
        "cwe": "CWE-1006",
    }


def rule_pwntools_missing(s):
    if not s.get("pwntools_missing"):
        return None
    return {
        "name": "pwntools not installed on scanner host - ELF audit skipped",
        "severity": "INFO",
        "evidence": f"ImportError: {s.get('pwntools_missing')}",
        "remediation": "Install pwntools >=4.10 in the scanner container: pip install pwntools",
        "cwe": "CWE-1006",
    }


def rule_pefile_missing(s):
    if not s.get("pefile_missing"):
        return None
    return {
        "name": "pefile not installed on scanner host - PE audit skipped",
        "severity": "INFO",
        "evidence": f"ImportError: {s.get('pefile_missing')}",
        "remediation": "Install pefile >=2023 in the scanner container: pip install pefile",
        "cwe": "CWE-1006",
    }


def rule_unsupported_format(s):
    if s.get("binary_macho_unsupported"):
        return {
            "name": "Mach-O binary detected - starter probes only audit ELF + PE",
            "severity": "INFO",
            "evidence": (
                "The uploaded file is a Mach-O (macOS / iOS) binary.  This starter only "
                "decodes ELF (Linux) and PE (Windows).  Mach-O mitigation audit (codesign "
                "flags, PAC, MTE, hardened runtime) ships in a later wave."
            ),
            "remediation": (
                "If you need Mach-O coverage now, re-run the binary through `otool -hv` + "
                "`codesign --display --verbose=4 --entitlements -` locally.  Watch for the "
                "VulnusLab Mac/iOS BOF wave landing soon."
            ),
            "cwe": "CWE-1006",
        }
    if s.get("binary_unknown_format"):
        return {
            "name": "Unrecognized binary header - audit could not proceed",
            "severity": "INFO",
            "evidence": (
                "The first 4 bytes of the uploaded file matched neither ELF (\\x7fELF) nor "
                "PE (MZ) nor any Mach-O magic.  Probable causes: file is encrypted / "
                "compressed / a shell script / corrupted upload."
            ),
            "remediation": (
                "Verify the file is the intended binary with `file <path>` locally.  "
                "Re-upload if it was truncated."
            ),
            "cwe": "CWE-1006",
        }
    return None


def rule_too_large(s):
    if not s.get("binary_too_large_mb"):
        return None
    return {
        "name": f"Binary too large for static audit ({s.get('binary_too_large_mb')} MB)",
        "severity": "INFO",
        "evidence": (
            f"The uploaded binary is {s.get('binary_too_large_mb')} MB; the starter caps "
            "static audit at 256MB to keep ROPgadget + capstone passes bounded."
        ),
        "remediation": (
            "Split the binary or strip debug info before re-uploading.  For bigger "
            "binaries the VulnusLab on-prem agent can be sized up to several GB."
        ),
        "cwe": "CWE-1006",
    }


def rule_elf_nx(s):
    p = s.get("elf_protections") or {}
    if _missing(p, "nx"):
        return {
            "name": "NX / DEP missing - stack is executable (classic shellcode-on-stack)",
            "severity": "CRITICAL",
            "cvss": "9.8",
            "cwe": "CWE-1265",
            "owasp": "A05:2021",
            "evidence": (
                f"pwntools ELF.nx = False on {s.get('binary_path', '?')}.  Any stack "
                "buffer overflow can place shellcode in the buffer and jump to it - no "
                "ROP chain needed."
            ),
            "remediation": (
                "1. Relink with -z noexecstack (GCC default since 2009; some embedded "
                "toolchains still strip it). "
                "2. Verify with `readelf -l <bin> | grep STACK` - the GNU_STACK segment "
                "must NOT have the X flag. "
                "3. If a third-party library re-enables it, raise an issue upstream."
            ),
        }
    return None


def rule_elf_pie(s):
    p = s.get("elf_protections") or {}
    if _missing(p, "pie"):
        return {
            "name": "PIE missing - code segment loads at a fixed address (ASLR ineffective)",
            "severity": "HIGH",
            "cvss": "7.5",
            "cwe": "CWE-1265",
            "owasp": "A05:2021",
            "evidence": (
                "pwntools ELF.pie = False.  Even with kernel ASLR enabled, the .text "
                "section sits at the same address on every run, so ret2text / ret2plt "
                "gadgets are reachable without a leak."
            ),
            "remediation": (
                "Compile and link with -fPIE -pie (executables) or -fPIC -shared "
                "(libraries).  Most modern distros ship PIE-by-default GCC/Clang specs "
                "files - update the toolchain or drop the offending CFLAGS override."
            ),
        }
    return None


def rule_elf_relro(s):
    p = s.get("elf_protections") or {}
    relro = (p.get("relro") or "").lower()
    if relro == "none":
        return {
            "name": "RELRO disabled - GOT entries are writable for ret2dlresolve / GOT-hijack",
            "severity": "HIGH",
            "cvss": "7.5",
            "cwe": "CWE-1265",
            "evidence": (
                "pwntools ELF.relro = none.  The GOT lives in writable .data, so any "
                "arbitrary-write primitive turns into instant code execution via GOT "
                "overwrite."
            ),
            "remediation": (
                "Relink with -Wl,-z,relro,-z,now (full RELRO).  -z,now also disables "
                "lazy binding so PLT stubs don't write back into the GOT at runtime."
            ),
        }
    if relro == "partial":
        return {
            "name": "RELRO is partial - lazy-binding leaves PLT entries writable",
            "severity": "MEDIUM",
            "cvss": "5.3",
            "cwe": "CWE-1265",
            "evidence": (
                "pwntools ELF.relro = Partial.  .got.plt is writable until the linker "
                "resolves each symbol - ret2dlresolve attacks can race against lazy "
                "binding."
            ),
            "remediation": (
                "Switch to full RELRO with -Wl,-z,relro,-z,now.  Startup will be a "
                "few ms slower but every PLT slot is read-only from process exec."
            ),
        }
    return None


def rule_elf_canary(s):
    p = s.get("elf_protections") or {}
    if _missing(p, "canary"):
        return {
            "name": "Stack canaries missing - buffer overflows reach saved RIP unchecked",
            "severity": "HIGH",
            "cvss": "8.1",
            "cwe": "CWE-121",
            "owasp": "A05:2021",
            "evidence": (
                "pwntools ELF.canary = False.  Functions with stack arrays do not get a "
                "guard word - linear overflow walks straight into the saved frame pointer "
                "and return address."
            ),
            "remediation": (
                "Compile with -fstack-protector-strong (or -fstack-protector-all for max "
                "coverage).  Verify with `objdump -d <bin> | grep __stack_chk_fail` - "
                "every vulnerable function must reference it."
            ),
        }
    return None


def rule_elf_fortify(s):
    p = s.get("elf_protections") or {}
    if _missing(p, "fortify_source"):
        return {
            "name": "FORTIFY_SOURCE missing - libc safe-* wrappers not in use",
            "severity": "MEDIUM",
            "cvss": "5.3",
            "cwe": "CWE-120",
            "evidence": (
                "No __*_chk symbols imported.  glibc's FORTIFY_SOURCE adds runtime "
                "size checks to memcpy / strcpy / sprintf / read / fgets when the "
                "destination size is known at compile time.  Without it, classic "
                "off-by-one and over-copy bugs survive into production."
            ),
            "remediation": (
                "Compile with -D_FORTIFY_SOURCE=3 (glibc 2.34+) or =2 (older).  Requires "
                "-O1 or higher.  Failing checks raise SIGABRT instead of corrupting "
                "memory, which is a far easier crash to triage."
            ),
        }
    return None


def rule_elf_rpath(s):
    p = s.get("elf_protections") or {}
    rpath = p.get("rpath") or []
    if not rpath:
        return None
    return {
        "name": "DT_RPATH / DT_RUNPATH present - library hijack possible if writable dirs",
        "severity": "MEDIUM",
        "cvss": "6.4",
        "cwe": "CWE-426",
        "evidence": f"Binary embeds rpath entries: {rpath}.  If any path is "
                    "world-writable, an attacker can drop a malicious shared object "
                    "there and the dynamic linker will load it before the system library.",
        "remediation": (
            "1. Strip DT_RPATH with `chrpath -d <bin>` or `patchelf --remove-rpath <bin>`. "
            "2. If you must keep one, set DT_RUNPATH (parsed AFTER LD_LIBRARY_PATH) and "
            "point it at a root-owned, mode-0755 directory. "
            "3. Audit all rpath entries are absolute and root-owned."
        ),
    }


def rule_pe_nx(s):
    p = s.get("pe_protections") or {}
    if _missing(p, "nx"):
        return {
            "name": "DEP / NX_COMPAT bit missing on PE - executable stack/heap",
            "severity": "CRITICAL",
            "cvss": "9.8",
            "cwe": "CWE-1265",
            "owasp": "A05:2021",
            "evidence": (
                f"pefile DllCharacteristics = {p.get('dll_characteristics_hex')}.  The "
                "IMAGE_DLLCHARACTERISTICS_NX_COMPAT bit (0x0100) is NOT set, so Windows "
                "will not enforce DEP for this image."
            ),
            "remediation": (
                "Re-link with /NXCOMPAT (MSVC: linker setting `Data Execution Prevention "
                "(DEP) = Yes`).  Mandatory for every modern Windows binary."
            ),
        }
    return None


def rule_pe_aslr(s):
    p = s.get("pe_protections") or {}
    if _missing(p, "pie"):
        return {
            "name": "ASLR / DYNAMIC_BASE bit missing on PE",
            "severity": "HIGH",
            "cvss": "7.5",
            "cwe": "CWE-1265",
            "evidence": (
                f"pefile DllCharacteristics = {p.get('dll_characteristics_hex')}.  Bit "
                "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040) is unset; the loader "
                "places this image at its preferred ImageBase every run."
            ),
            "remediation": (
                "Re-link with /DYNAMICBASE (and /HIGHENTROPYVA for 64-bit).  MSVC: "
                "linker setting `Randomized Base Address = Yes`."
            ),
        }
    return None


def rule_pe_high_entropy(s):
    p = s.get("pe_protections") or {}
    if p.get("bits") == 64 and _missing(p, "aslr_high_entropy"):
        return {
            "name": "PE64 HIGH_ENTROPY_VA missing - ASLR limited to 32-bit space",
            "severity": "MEDIUM",
            "cvss": "5.3",
            "cwe": "CWE-1265",
            "evidence": (
                "64-bit PE without HIGH_ENTROPY_VA (0x0020) gets only 24 bits of "
                "randomization - feasible to brute-force from a remote service over "
                "thousands of requests."
            ),
            "remediation": "Re-link with /HIGHENTROPYVA (default for VS2019+).",
        }
    return None


def rule_pe_canary(s):
    p = s.get("pe_protections") or {}
    if _missing(p, "canary"):
        return {
            "name": "GS / __security_cookie missing on PE - stack overflow unchecked",
            "severity": "HIGH",
            "cvss": "8.1",
            "cwe": "CWE-121",
            "evidence": (
                "No reference to __security_cookie / __security_check_cookie in the "
                "binary.  /GS-protected functions are absent or have been disabled."
            ),
            "remediation": (
                "Recompile with /GS (MSVC C/C++ -> Code Generation -> Buffer Security "
                "Check = Yes).  Required for every binary that touches untrusted input."
            ),
        }
    return None


def rule_pe_cfg(s):
    p = s.get("pe_protections") or {}
    if _missing(p, "cfg"):
        return {
            "name": "Control-Flow Guard (CFG) missing on PE - indirect-call gadgets unchecked",
            "severity": "HIGH",
            "cvss": "7.5",
            "cwe": "CWE-1265",
            "evidence": (
                f"pefile DllCharacteristics = {p.get('dll_characteristics_hex')}.  Bit "
                "IMAGE_DLLCHARACTERISTICS_GUARD_CF (0x4000) is unset; indirect calls / "
                "vtable dispatches are not validated against the CFG bitmap."
            ),
            "remediation": (
                "Re-link with /GUARD:CF.  Available since VS2015.  Pairs with /CETCOMPAT "
                "for shadow-stack on Win11."
            ),
        }
    return None


def rule_pe_safeseh(s):
    p = s.get("pe_protections") or {}
    if p.get("bits") == 32 and _missing(p, "safeseh"):
        return {
            "name": "SafeSEH missing on 32-bit PE - SEH overwrite exploitation feasible",
            "severity": "HIGH",
            "cvss": "7.5",
            "cwe": "CWE-1265",
            "evidence": (
                "32-bit PE without SafeSEH (SEHandlerCount = 0).  A stack overflow that "
                "reaches the SEH chain can hijack control with a pop/pop/ret gadget."
            ),
            "remediation": (
                "Re-link with /SAFESEH.  All third-party .obj/.lib inputs must also be "
                "SafeSEH-aware or the linker drops the flag."
            ),
        }
    return None


def rule_modern_cet_absent(s):
    p = s.get("elf_protections") or {}
    if p.get("kind") != "elf":
        return None
    if p.get("cet_ibt") or p.get("cet_shadow_stack"):
        return None
    return {
        "name": "Intel CET (IBT / Shadow Stack) not advertised in .note.gnu.property",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-1265",
        "evidence": (
            "No GNU_PROPERTY_X86_FEATURE_1_IBT / SHSTK markers in the ELF.  On 12th-gen+ "
            "Intel + Linux 5.18+ the kernel can enforce indirect-branch tracking and a "
            "shadow stack, but only if the binary opts in at build time."
        ),
        "remediation": (
            "Compile with -fcf-protection=full (GCC/Clang >= 9).  Requires linking only "
            "CET-aware libraries (glibc 2.36+ ships them)."
        ),
    }


def rule_positive_elf(s):
    p = s.get("elf_protections") or {}
    if p.get("kind") != "elf":
        return None
    if not (p.get("nx") and p.get("pie") and p.get("canary")
            and (p.get("relro") or "").lower() == "full" and p.get("fortify_source")):
        return None
    return {
        "name": "ELF binary ships with full modern stack mitigations",
        "severity": "POSITIVE",
        "evidence": (
            f"NX + PIE + Stack Canary + RELRO=full + FORTIFY_SOURCE all present on "
            f"{s.get('binary_path', '?')}.  Memory-corruption bugs in this binary "
            "require an info leak + ROP chain (not stack shellcode)."
        ),
        "remediation": (
            "Maintain build flags in CI - any future regression to partial-RELRO / "
            "missing-PIE will surface in this scan.  Add CET / IBT next."
        ),
        "cwe": "CWE-1265",
    }


def rule_positive_pe(s):
    p = s.get("pe_protections") or {}
    if p.get("kind") != "pe":
        return None
    if not (p.get("nx") and p.get("pie") and p.get("canary") and p.get("cfg")):
        return None
    return {
        "name": "PE binary ships with full modern Windows mitigations",
        "severity": "POSITIVE",
        "evidence": (
            "NX + DYNAMICBASE + /GS + CFG all enabled.  Stack overflows now require "
            "an info leak + ROP + CFG bypass to exploit."
        ),
        "remediation": (
            "Keep the build flags in CI.  Consider /CETCOMPAT (CET shadow stack) and "
            "/INTEGRITYCHECK for signed-only loading on Win11."
        ),
        "cwe": "CWE-1265",
    }


BINARY_PROTECTION_AUDIT_FINDING_RULES = [
    rule_input_missing,
    rule_pwntools_missing,
    rule_pefile_missing,
    rule_unsupported_format,
    rule_too_large,
    rule_elf_nx,
    rule_elf_pie,
    rule_elf_relro,
    rule_elf_canary,
    rule_elf_fortify,
    rule_elf_rpath,
    rule_pe_nx,
    rule_pe_aslr,
    rule_pe_high_entropy,
    rule_pe_canary,
    rule_pe_cfg,
    rule_pe_safeseh,
    rule_modern_cet_absent,
    rule_positive_elf,
    rule_positive_pe,
]
