"""dangerous_function_detect - findings rules.

Severity model:
  CRITICAL - gets() call site present (impossible to use safely)
  HIGH     - system() / popen() / exec*() call site (command injection surface)
  MEDIUM   - strcpy / strcat / sprintf / scanf%s / memcpy / strncpy
  LOW      - vulnerable function imported but no call site located (statically linked stub?)
  INFO     - library missing / unsupported arch / binary missing
  POSITIVE - none of the dangerous primitives are imported AND _chk variants used
"""


CRITICAL_FUNCS = {"gets"}
HIGH_FUNCS     = {"system", "popen", "execl", "execlp", "execle",
                  "execv", "execvp", "execve"}
MEDIUM_FUNCS   = {"strcpy", "strcat", "sprintf", "vsprintf",
                  "scanf", "fscanf", "vscanf",
                  "memcpy", "strncpy",
                  "lstrcpya", "lstrcpyw", "lstrcata", "lstrcatw",
                  "_mbscpy", "_mbscat"}


def rule_input_missing(s):
    if not s.get("binary_path_missing"):
        return None
    return {
        "name": "dangerous_function_detect skipped - binary file not found",
        "severity": "INFO",
        "evidence": "ScanRequest.target did not resolve to a readable file on disk.",
        "remediation": "Re-run with target = absolute path to an uploaded ELF / PE binary.",
        "cwe": "CWE-1006",
    }


def rule_library_missing(s):
    if not s.get("library_missing"):
        return None
    return {
        "name": f"Dangerous-function probe could not run - {s.get('library_missing')}",
        "severity": "INFO",
        "evidence": "Required disasm library missing from scanner image.",
        "remediation": (
            "Install in the scanner container: pip install pwntools capstone pefile."
        ),
        "cwe": "CWE-1006",
    }


def rule_parse_error(s):
    if not s.get("parse_error"):
        return None
    return {
        "name": "Binary failed to parse - dangerous-function probe skipped",
        "severity": "INFO",
        "evidence": str(s.get("parse_error"))[:300],
        "remediation": (
            "Verify the binary opens with `objdump -d` / `dumpbin` locally; "
            "re-upload if it was truncated in transit."
        ),
        "cwe": "CWE-1006",
    }


def rule_unsupported_arch(s):
    if not s.get("unsupported_arch"):
        return None
    return {
        "name": f"Architecture {s.get('unsupported_arch')} not yet supported",
        "severity": "INFO",
        "evidence": (
            "The starter only disassembles i386 / x86_64 / ARM32 / ARM64.  "
            "MIPS / PowerPC / RISC-V will land in a later wave."
        ),
        "remediation": "Use radare2 / Ghidra for now; raise a request to add this arch.",
        "cwe": "CWE-1006",
    }


def rule_unknown_format(s):
    if not s.get("binary_unknown_format"):
        return None
    return {
        "name": "Unrecognized binary header - dangerous-function probe skipped",
        "severity": "INFO",
        "evidence": "First 4 bytes matched neither ELF (\\x7fELF) nor PE (MZ).",
        "remediation": "Verify the file with `file <path>` locally and re-upload.",
        "cwe": "CWE-1006",
    }


def _sample_sites(call_sites: list, callees: set, limit: int = 5) -> list[str]:
    out: list[str] = []
    for site in call_sites:
        if site.get("callee") in callees:
            caller = site.get("caller") or "?"
            off    = site.get("caller_offset") or ""
            out.append(f"{site.get('callee')} <- {caller} @ {off}".strip())
            if len(out) >= limit:
                break
    return out


def rule_critical_gets(s):
    cb = s.get("calls_by_callee") or {}
    imports = set(s.get("dangerous_imports") or [])
    hits = CRITICAL_FUNCS & (set(cb.keys()) | imports)
    if not hits:
        return None
    total = sum(cb.get(f, 0) for f in hits) or len(hits)
    sample = _sample_sites(s.get("call_sites") or [], hits)
    return {
        "name": f"gets() call site present - {total} use(s) of an always-unsafe primitive",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-242",
        "owasp": "A05:2021",
        "evidence": (
            "gets() reads stdin into a fixed buffer with no length argument - "
            "literally undefined behaviour by design and removed from C11.  "
            f"Sample call sites: {sample or '(no caller attribution)'}."
        ),
        "remediation": (
            "1. Replace every gets() with fgets(buf, sizeof(buf), stdin). "
            "2. Audit history for other gets-style helpers in custom libraries. "
            "3. Add `-Wall -Werror` so the deprecation warning blocks the build. "
            "4. Run this probe in CI on every release artifact."
        ),
    }


def rule_high_command_injection(s):
    cb = s.get("calls_by_callee") or {}
    imports = set(s.get("dangerous_imports") or [])
    hits = HIGH_FUNCS & (set(cb.keys()) | imports)
    if not hits:
        return None
    total = sum(cb.get(f, 0) for f in hits) or len(hits)
    sample = _sample_sites(s.get("call_sites") or [], hits)
    return {
        "name": f"system()/exec*() call sites present - {total} command-execution sink(s)",
        "severity": "HIGH",
        "cvss": "8.8",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "evidence": (
            f"Calls to {sorted(hits)} located.  Each call site is a candidate command "
            "injection: if any argument touches user input the attacker controls the "
            "shell.  Sample sites: " + ("; ".join(sample) if sample else "(IAT-level hits)")
        ),
        "remediation": (
            "1. Replace system()/popen() with execve()-style argv arrays and avoid /bin/sh. "
            "2. Strict-allowlist arguments at the call site - never concatenate user input. "
            "3. If shell is unavoidable, use posix_spawn with no PATH lookup. "
            "4. Audit the source files containing these symbols (see Sample sites)."
        ),
    }


def rule_medium_unsafe_string(s):
    cb = s.get("calls_by_callee") or {}
    imports = set(s.get("dangerous_imports") or [])
    hits = MEDIUM_FUNCS & (set(cb.keys()) | imports)
    if not hits:
        return None
    total = sum(cb.get(f, 0) for f in hits) or len(hits)
    sample = _sample_sites(s.get("call_sites") or [], hits)
    return {
        "name": f"Unsafe string / memcpy primitives present - {total} call site(s)",
        "severity": "MEDIUM",
        "cvss": "6.5",
        "cwe": "CWE-120",
        "owasp": "A05:2021",
        "evidence": (
            f"Calls to {sorted(hits)} located.  Each call can overflow the destination "
            "if the source length exceeds the destination capacity.  Sample sites: "
            + ("; ".join(sample) if sample else "(IAT-level hits)")
        ),
        "remediation": (
            "1. Replace strcpy/strcat with strlcpy/strlcat (BSD) or snprintf. "
            "2. Replace sprintf with snprintf and check return value. "
            "3. Replace scanf/fscanf with explicit width: scanf(\"%127s\", buf). "
            "4. For memcpy with attacker-controlled size, add `if (n > sizeof dst) abort();`. "
            "5. Compile with -D_FORTIFY_SOURCE=3 to surface the rest automatically."
        ),
    }


def rule_fortify_present(s):
    chk = s.get("fortify_chk_used") or []
    if not chk:
        return None
    return {
        "name": f"FORTIFY_SOURCE _chk variants in use ({len(chk)} symbol(s))",
        "severity": "POSITIVE",
        "evidence": (
            f"Detected glibc _chk wrappers: {chk[:8]}.  Some bounds-checked calls are in "
            "place - keep going and remove the raw siblings too."
        ),
        "remediation": (
            "Recompile with -D_FORTIFY_SOURCE=3 and a recent glibc so EVERY copy reaches "
            "the _chk fast path.  Then re-run this scan - dangerous-function count should "
            "drop further."
        ),
        "cwe": "CWE-120",
    }


def rule_positive(s):
    cb = s.get("calls_by_callee") or {}
    imports = set(s.get("dangerous_imports") or [])
    if cb or imports:
        return None
    if s.get("binary_path_missing") or s.get("library_missing"):
        return None
    if s.get("parse_error") or s.get("unsupported_arch") or s.get("binary_unknown_format"):
        return None
    return {
        "name": "No dangerous libc primitives located - good static hygiene",
        "severity": "POSITIVE",
        "evidence": (
            "Probe walked the symbol table + .text and found no calls to "
            "gets / strcpy / strcat / sprintf / scanf / system / exec* / "
            "memcpy / strncpy.  Static side of buffer-overflow risk is clean."
        ),
        "remediation": (
            "Maintain the discipline.  Keep -D_FORTIFY_SOURCE=3 + -Wformat-security + "
            "-Wstack-usage in the build.  Run this scan in CI on every release."
        ),
        "cwe": "CWE-120",
    }


DANGEROUS_FUNCTION_DETECT_FINDING_RULES = [
    rule_input_missing,
    rule_library_missing,
    rule_parse_error,
    rule_unsupported_arch,
    rule_unknown_format,
    rule_critical_gets,
    rule_high_command_injection,
    rule_medium_unsafe_string,
    rule_fortify_present,
    rule_positive,
]
