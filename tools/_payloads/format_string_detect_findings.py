"""format_string_detect - findings rules.

Severity model:
  HIGH     - >=1 printf-family call site where format arg loaded from register/memory
             (attacker-controlled format -> arbitrary read/write via %n / %s)
  MEDIUM   - printf-family imports present + arch not x86 (probe couldn't analyze)
  LOW      - PE binary with printf imports (disasm skipped for PE in this starter)
  INFO     - libs missing / file missing / unknown format
  POSITIVE - imports present but EVERY call site uses an immediate (.rodata) format
"""

CWE_FMT = "CWE-134"
OWASP_FMT = "A03:2021"


def rule_input_missing(s):
    if not s.get("binary_path_missing"):
        return None
    return {
        "name": "format_string_detect skipped - binary file not found",
        "severity": "INFO",
        "evidence": "ScanRequest.target did not resolve to a readable file.",
        "remediation": "Re-run with target = absolute path to an uploaded binary.",
        "cwe": "CWE-1006",
    }


def rule_too_large(s):
    if not s.get("binary_too_large_mb"):
        return None
    return {
        "name": f"Binary too large for format-string disasm ({s.get('binary_too_large_mb')} MB)",
        "severity": "INFO",
        "evidence": "Starter caps disasm input at 256MB.",
        "remediation": "Strip / split the binary then re-run.",
        "cwe": "CWE-1006",
    }


def rule_library_missing(s):
    if not s.get("library_missing"):
        return None
    return {
        "name": f"format_string_detect could not run - {s.get('library_missing')}",
        "severity": "INFO",
        "evidence": "Required library missing.",
        "remediation": (
            "Install in the scanner container: pip install pwntools capstone pefile."
        ),
        "cwe": "CWE-1006",
    }


def rule_parse_error(s):
    if not s.get("parse_error"):
        return None
    return {
        "name": "Binary failed to parse - format_string probe skipped",
        "severity": "INFO",
        "evidence": str(s.get("parse_error"))[:300],
        "remediation": "Verify with `objdump -d` / `dumpbin` locally; re-upload if needed.",
        "cwe": "CWE-1006",
    }


def rule_unknown_format(s):
    if not s.get("binary_unknown_format"):
        return None
    return {
        "name": "Unrecognized binary header - format_string probe skipped",
        "severity": "INFO",
        "evidence": "First 4 bytes matched neither ELF (\\x7fELF) nor PE (MZ).",
        "remediation": "Verify with `file <path>` locally and re-upload.",
        "cwe": "CWE-1006",
    }


def _sample(sites: list, limit: int = 5) -> str:
    if not sites:
        return ""
    out: list[str] = []
    for s in sites[:limit]:
        out.append(
            f"{s.get('callee')} <- {s.get('caller')} @ {s.get('call_addr')} "
            f"(loader: {s.get('loader')}, kind={s.get('classification')})"
        )
    return " | ".join(out)


def rule_high_suspect_sites(s):
    sites = s.get("suspect_sites") or []
    if not sites:
        return None
    return {
        "name": (f"Format-string vulnerability candidates - {len(sites)} call site(s) "
                 "load printf format arg from register/memory"),
        "severity": "HIGH",
        "cvss": "8.1",
        "cwe": CWE_FMT,
        "owasp": OWASP_FMT,
        "evidence": (
            "Each call site below has its format-string argument supplied from a "
            "register-to-register move or a memory dereference - which means the "
            "format string is NOT a compile-time constant.  If any data path lets "
            "an attacker reach this site with user input as the format, %n / %s "
            f"primitives give arbitrary write / read.  Sample sites: {_sample(sites)}"
        ),
        "remediation": (
            "1. For every site, change `printf(fmt, ...)` to `printf(\"%s\", fmt)` "
            "OR a function that takes the format string literally (puts / fputs / "
            "fwrite). "
            "2. Add `-Wformat -Wformat-security -Werror=format-security` to the build - "
            "GCC/Clang refuse to compile a printf without a literal format. "
            "3. Pair with stack canaries + RELRO so the write primitive is harder to "
            "land on a useful target. "
            "4. Re-run this scan in CI; suspect_total should hit zero."
        ),
    }


def rule_medium_arch_unsupported(s):
    if not s.get("arch_unsupported_for_disasm"):
        return None
    imports = s.get("format_imports") or []
    if not imports:
        return None
    return {
        "name": ("printf-family imports present but architecture not in starter's "
                 "disasm coverage - manual review needed"),
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": CWE_FMT,
        "evidence": (
            f"Binary uses: {imports}.  This starter only does flow analysis on "
            f"x86 / x86_64.  Arch reported: {s.get('binary_arch') or 'unknown'}."
        ),
        "remediation": (
            "Review the source with `-Wformat-security` enabled or disassemble manually "
            "with radare2 / Ghidra.  Watch for the ARM port of this probe in a later wave."
        ),
    }


def rule_low_pe_disasm_skipped(s):
    if not s.get("pe_disasm_skipped"):
        return None
    imports = s.get("format_imports") or []
    if not imports:
        return None
    return {
        "name": (f"PE binary imports {len(imports)} printf-family function(s); "
                 "format-arg flow analysis not yet implemented for PE"),
        "severity": "LOW",
        "cvss": "3.1",
        "cwe": CWE_FMT,
        "evidence": (
            f"PE imports: {imports}.  Windows uses RCX/RDX/R8/R9 for the first four "
            "args, then stack - the SysV-x86_64 heuristic from this starter does not "
            "apply.  Static review of the source recommended."
        ),
        "remediation": (
            "Enable /sdl on MSVC (security development lifecycle warnings include "
            "format-string).  Schedule a manual disasm pass.  PE format-arg flow "
            "analysis ships in a later wave."
        ),
    }


def rule_positive_only_safe(s):
    if s.get("binary_path_missing") or s.get("library_missing") or s.get("parse_error"):
        return None
    imports = s.get("format_imports") or []
    if not imports:
        return None
    suspect = s.get("suspect_sites") or []
    safe    = s.get("safe_sites") or []
    if suspect:
        return None
    if not safe:
        return None
    return {
        "name": (f"All {len(safe)} printf-family call site(s) use a literal "
                 "(.rodata) format string"),
        "severity": "POSITIVE",
        "evidence": (
            f"Imports: {imports}.  Every located call site loads the format arg from "
            "[rip + offset] (immediate) - no register-to-register or stack-loaded "
            "format strings detected."
        ),
        "remediation": (
            "Keep `-Wformat-security -Werror=format-security` in the build to prevent "
            "any future regression.  Re-run this scan on each release."
        ),
        "cwe": CWE_FMT,
    }


FORMAT_STRING_DETECT_FINDING_RULES = [
    rule_input_missing,
    rule_too_large,
    rule_library_missing,
    rule_parse_error,
    rule_unknown_format,
    rule_high_suspect_sites,
    rule_medium_arch_unsupported,
    rule_low_pe_disasm_skipped,
    rule_positive_only_safe,
]
