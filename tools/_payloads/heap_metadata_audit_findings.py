"""heap_metadata_audit - findings rules.

Severity model:
  HIGH     - static-linked glibc lacking safe-linking (<2.32)
  MEDIUM   - glibc 2.27-2.31 (tcache without safe-linking) OR no safe-linking marker
  LOW      - heap funcs imported but unable to determine libc generation
  INFO     - libs missing / file missing / unknown binary format
  POSITIVE - modern glibc (2.34+) statically linked OR dynamic with safe-linking marker
"""

CWE_HEAP   = "CWE-415"   # double-free / UAF (heap metadata corruption family)
CWE_OOB    = "CWE-787"   # OOB write (often via heap corruption)
CWE_DESIGN = "CWE-1265"  # missing exploit mitigation


def rule_input_missing(s):
    if not s.get("binary_path_missing"):
        return None
    return {
        "name": "heap_metadata_audit skipped - binary file not found",
        "severity": "INFO",
        "evidence": "ScanRequest.target did not resolve to a readable file.",
        "remediation": "Re-run with target = absolute path to an uploaded binary.",
        "cwe": "CWE-1006",
    }


def rule_too_large(s):
    if not s.get("binary_too_large_mb"):
        return None
    return {
        "name": f"Binary too large for heap audit ({s.get('binary_too_large_mb')} MB)",
        "severity": "INFO",
        "evidence": "Starter caps heap audit input at 256MB.",
        "remediation": "Strip / split the binary then re-run.",
        "cwe": "CWE-1006",
    }


def rule_library_missing(s):
    if not s.get("library_missing"):
        return None
    return {
        "name": f"Heap probe could not run - {s.get('library_missing')}",
        "severity": "INFO",
        "evidence": "Required library missing.",
        "remediation": "Install in the scanner container: pip install pwntools pefile.",
        "cwe": "CWE-1006",
    }


def rule_parse_error(s):
    if not s.get("parse_error"):
        return None
    return {
        "name": "Binary failed to parse - heap probe skipped",
        "severity": "INFO",
        "evidence": str(s.get("parse_error"))[:300],
        "remediation": "Verify with `objdump -d` / `dumpbin` locally; re-upload if needed.",
        "cwe": "CWE-1006",
    }


def rule_unknown_format(s):
    if not s.get("binary_unknown_format"):
        return None
    return {
        "name": "Unrecognized binary header - heap probe skipped",
        "severity": "INFO",
        "evidence": "First 4 bytes matched neither ELF (\\x7fELF) nor PE (MZ).",
        "remediation": "Verify with `file <path>` locally and re-upload.",
        "cwe": "CWE-1006",
    }


def rule_high_static_old_glibc(s):
    if not s.get("static_glibc"):
        return None
    gmax = (s.get("glibc_max_seen") or "0.0").split(".")
    try:
        major, minor = int(gmax[0]), int(gmax[1])
    except Exception:
        return None
    if (major, minor) >= (2, 32):
        return None
    return {
        "name": (f"Statically linked glibc {s.get('glibc_max_seen')} predates "
                 "safe-linking - tcache / fastbin attacks are unmitigated"),
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": CWE_HEAP,
        "owasp": "A05:2021",
        "evidence": (
            f"Binary embeds GLIBC strings up to {s.get('glibc_max_seen')} (statically "
            "linked).  Versions <2.32 do not obfuscate the free-list `next` pointers; "
            "any heap overflow + write primitive lets an attacker chain "
            "tcache_dup / fastbin_dup style attacks straight to write-anywhere."
        ),
        "remediation": (
            "1. Rebuild against glibc >= 2.34 (or musl >=1.2.4 with safe-linking). "
            "2. Stop static-linking glibc if you can - dynamic linking inherits the "
            "OS-supplied (patched) allocator. "
            "3. If you MUST static-link, pin to a vetted release and run this scan "
            "in CI to alert on regressions."
        ),
    }


def rule_medium_old_dynamic_glibc(s):
    if s.get("static_glibc"):
        return None
    gmax = (s.get("glibc_max_seen") or "")
    if not gmax:
        return None
    try:
        major, minor = (int(x) for x in gmax.split("."))
    except Exception:
        return None
    # 2.27..2.31 = tcache present BUT no safe-linking
    if not (major == 2 and 27 <= minor <= 31):
        return None
    return {
        "name": (f"Binary references GLIBC {gmax} - tcache present without safe-linking"),
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": CWE_HEAP,
        "evidence": (
            f"GLIBC version strings up to {gmax} embedded.  The 2.27 family introduced "
            "tcache (small-allocation fast path) but did NOT add safe-linking "
            "(pointer-obfuscation) until 2.32.  An attacker with a single UAF can "
            "perform tcache poisoning to redirect a future malloc()."
        ),
        "remediation": (
            "Upgrade the runtime to glibc >= 2.32 (Debian 11+, Ubuntu 20.10+, RHEL 9, "
            "Alpine 3.16+).  This is a runtime upgrade, not a binary rebuild - the "
            "moment the container ships a newer glibc the protection is live."
        ),
    }


def rule_medium_no_safelinking_marker(s):
    if s.get("safe_linking_marker_present"):
        return None
    if s.get("static_glibc"):
        # already covered by HIGH rule if old
        return None
    if not s.get("tcache_marker_present"):
        return None
    return {
        "name": "tcache markers present without safe-linking string - likely glibc 2.27-2.31",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": CWE_HEAP,
        "evidence": (
            "The binary references tcache_entry / tcache_perthread_struct but the "
            "PROTECT_PTR / safe-linking string is absent.  Heuristically this points to "
            "glibc 2.27-2.31, which has tcache but no pointer obfuscation."
        ),
        "remediation": (
            "Upgrade runtime to glibc >= 2.32 OR re-link against musl 1.2.4+ for stronger "
            "allocator hardening."
        ),
    }


def rule_low_heap_only(s):
    if s.get("static_glibc"):
        return None
    if s.get("glibc_max_seen"):
        return None
    imp = s.get("heap_imports") or []
    if not imp:
        return None
    return {
        "name": (f"Binary imports {len(imp)} heap function(s) - libc version not "
                 "determinable from this static view"),
        "severity": "LOW",
        "cvss": "3.7",
        "cwe": CWE_HEAP,
        "evidence": (
            f"Heap imports: {imp[:8]}.  Either the binary is dynamic-linked (libc lives "
            "in the runtime environment) or libc strings were stripped.  Recommend "
            "running this probe inside the production container to see the real glibc."
        ),
        "remediation": (
            "Re-run the scan against the container image with the binary's runtime "
            "libc resolvable, or run `ldd <bin> && /lib/x86_64-linux-gnu/libc.so.6 --version` "
            "to capture the live libc string."
        ),
    }


def rule_positive_modern(s):
    if s.get("binary_path_missing") or s.get("library_missing") or s.get("parse_error"):
        return None
    if s.get("static_glibc"):
        gmax = (s.get("glibc_max_seen") or "0.0").split(".")
        try:
            major, minor = int(gmax[0]), int(gmax[1])
        except Exception:
            return None
        if (major, minor) >= (2, 34):
            return {
                "name": f"Statically linked glibc {s.get('glibc_max_seen')} - modern allocator hardening",
                "severity": "POSITIVE",
                "evidence": (
                    f"Binary statically links glibc {s.get('glibc_max_seen')}, which "
                    "includes safe-linking, tcache double-free detection, and pthread "
                    "merge.  Heap exploitation requires multiple primitive leaks."
                ),
                "remediation": (
                    "Keep pinning to the latest released glibc.  Watch CVE feeds for the "
                    "specific minor version and re-build on a cadence."
                ),
                "cwe": CWE_HEAP,
            }
    if s.get("safe_linking_marker_present"):
        return {
            "name": "safe-linking marker present (glibc 2.32+ runtime)",
            "severity": "POSITIVE",
            "evidence": (
                "Binary or environment exposes the PROTECT_PTR string introduced in "
                "glibc 2.32.  Free-list `next` pointers are XOR-obfuscated, so tcache "
                "poisoning requires an additional leak primitive."
            ),
            "remediation": (
                "Stay on the upgrade path: glibc 2.36+ adds further hardening (bin "
                "double-linked checks).  Track distro stable releases."
            ),
            "cwe": CWE_HEAP,
        }
    return None


HEAP_METADATA_AUDIT_FINDING_RULES = [
    rule_input_missing,
    rule_too_large,
    rule_library_missing,
    rule_parse_error,
    rule_unknown_format,
    rule_high_static_old_glibc,
    rule_medium_old_dynamic_glibc,
    rule_medium_no_safelinking_marker,
    rule_low_heap_only,
    rule_positive_modern,
]
