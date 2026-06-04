"""rop_gadget_finder - findings rules.

Severity model:
  HIGH     - ROP chain feasible (>=2 pop;ret + arg-loader/syscall present)
  MEDIUM   - any pop;ret OR stack-pivot gadget present (chain becomes feasible
             once an info-leak or arbitrary-write primitive is added)
  LOW      - gadgets present but no pop;ret / syscall (rare, mostly leave;ret)
  INFO     - ROPgadget missing / failed / binary not found
  POSITIVE - 0 ROP-useful gadgets located (statically linked stripped tiny binary)
"""


def rule_input_missing(s):
    if not s.get("binary_path_missing"):
        return None
    return {
        "name": "rop_gadget_finder skipped - binary file not found",
        "severity": "INFO",
        "evidence": "ScanRequest.target did not resolve to a readable file.",
        "remediation": "Re-run with target = absolute path to an uploaded binary.",
        "cwe": "CWE-1006",
    }


def rule_too_large(s):
    if not s.get("binary_too_large_mb"):
        return None
    return {
        "name": f"Binary too large for ROPgadget pass ({s.get('binary_too_large_mb')} MB)",
        "severity": "INFO",
        "evidence": "Starter caps ROPgadget input at 256MB to keep run-time bounded.",
        "remediation": "Strip debug info / split the binary then re-run.",
        "cwe": "CWE-1006",
    }


def rule_ropgadget_missing(s):
    if not s.get("ropgadget_missing"):
        return None
    return {
        "name": "ROPgadget binary not installed on scanner host",
        "severity": "INFO",
        "evidence": "shutil.which('ROPgadget') returned None.",
        "remediation": (
            "Install ROPgadget in the scanner container: "
            "`pip install ROPgadget` (or `apt install ropgadget` on Kali)."
        ),
        "cwe": "CWE-1006",
    }


def rule_ropgadget_error(s):
    if not s.get("ropgadget_error"):
        return None
    return {
        "name": "ROPgadget invocation failed",
        "severity": "INFO",
        "evidence": f"ROPgadget produced no gadget output: {s.get('ropgadget_error')}",
        "remediation": (
            "Run ROPgadget locally against the same binary to reproduce. "
            "Common causes: unrecognized architecture, stripped raw blob, packed ELF."
        ),
        "cwe": "CWE-1006",
    }


def _samples_str(samples: list) -> str:
    if not samples:
        return ""
    lines = []
    for sm in samples[:5]:
        addr = sm.get("addr") or "?"
        asm  = sm.get("asm")  or "?"
        lines.append(f"{addr}: {asm}")
    return " | ".join(lines)


def rule_high_chain_feasible(s):
    if not s.get("ropgadget_chain_feasible"):
        return None
    br = s.get("ropgadget_useful_breakdown") or {}
    samples = _samples_str(s.get("ropgadget_samples") or [])
    return {
        "name": (f"ROP chain feasible - {br.get('pop_ret', 0)} pop;ret, "
                 f"{br.get('syscall_ret', 0)} syscall;ret, "
                 f"{s.get('ropgadget_sysv_arg_loaders', 0)} SysV arg-loaders"),
        "severity": "HIGH",
        "cvss": "8.1",
        "cwe": "CWE-1265",
        "owasp": "A05:2021",
        "evidence": (
            f"ROPgadget located {s.get('ropgadget_total_gadgets', 0)} total gadgets, "
            "including the building blocks of a SysV-x86_64 syscall chain "
            "(pop rdi; ret  +  syscall; ret  / int 0x80; ret).  An attacker with a "
            "single stack-overflow primitive can chain these into execve(\"/bin/sh\") "
            "even with NX enabled.  Top samples: " + (samples or "(none)")
        ),
        "remediation": (
            "1. Enable PIE so gadget addresses are randomized per run. "
            "2. Adopt CET-IBT + Shadow Stack (-fcf-protection=full) to invalidate "
            "indirect-branch gadgets. "
            "3. Strip dead code with -Wl,--gc-sections and LTO so fewer gadgets "
            "survive linking. "
            "4. Run this scan + dangerous_function_detect on every build - if both "
            "find a primitive AND chain, the binary is one info-leak away from RCE."
        ),
    }


def rule_medium_gadgets_present(s):
    if s.get("ropgadget_chain_feasible"):
        return None  # already covered by HIGH rule
    br = s.get("ropgadget_useful_breakdown") or {}
    if not (br.get("pop_ret") or br.get("stack_pivot") or br.get("syscall_ret")):
        return None
    samples = _samples_str(s.get("ropgadget_samples") or [])
    return {
        "name": ("ROP gadgets present - pop_ret="
                 f"{br.get('pop_ret', 0)} stack_pivot={br.get('stack_pivot', 0)} "
                 f"syscall_ret={br.get('syscall_ret', 0)}"),
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-1265",
        "evidence": (
            "ROP primitives located.  Not yet a complete chain (missing arg-loaders), "
            "but ONE info-leak + one extra useful gadget makes this binary chain-ready. "
            f"Top samples: {samples or '(none)'}"
        ),
        "remediation": (
            "Same hardening as the HIGH rule (PIE, CET, LTO, strip).  Treat any future "
            "library upgrade that adds rdi/rsi pop;ret pairs as a regression."
        ),
    }


def rule_low_ret_only(s):
    if s.get("ropgadget_chain_feasible"):
        return None
    br = s.get("ropgadget_useful_breakdown") or {}
    if not br.get("ret_only") and not br.get("leave_ret"):
        return None
    if br.get("pop_ret") or br.get("syscall_ret"):
        return None
    return {
        "name": "Only trivial ret / leave;ret gadgets present - chain requires more work",
        "severity": "LOW",
        "cvss": "3.1",
        "cwe": "CWE-1265",
        "evidence": (
            f"{br.get('ret_only', 0)} bare-ret + {br.get('leave_ret', 0)} leave;ret "
            "gadgets located.  These are useful for stack alignment / pivot but not for "
            "control-flow on their own."
        ),
        "remediation": (
            "Address the protection-audit findings first.  If NX + Canary land but ROP "
            "gadgets remain, an attacker still needs an arg-loader gadget to chain."
        ),
    }


def rule_positive(s):
    if s.get("binary_path_missing") or s.get("ropgadget_missing") or s.get("ropgadget_error"):
        return None
    total = s.get("ropgadget_total_gadgets") or 0
    br = s.get("ropgadget_useful_breakdown") or {}
    if total > 0:
        return None
    return {
        "name": "ROPgadget found zero gadgets - small / packed / non-executable section",
        "severity": "POSITIVE",
        "evidence": (
            "ROPgadget produced no parseable gadget output.  Either the binary is tiny "
            "and stripped, packed (UPX), or the .text section is structured such that "
            "ROP scanning fails.  Verify by running ROPgadget locally."
        ),
        "remediation": (
            "Confirm with `ROPgadget --binary <path>` locally.  If packing is the cause, "
            "the unpacked runtime image will have the gadgets - the test scan should be "
            "run on the unpacked artifact."
        ),
        "cwe": "CWE-1265",
    }


ROP_GADGET_FINDER_FINDING_RULES = [
    rule_input_missing,
    rule_too_large,
    rule_ropgadget_missing,
    rule_ropgadget_error,
    rule_high_chain_feasible,
    rule_medium_gadgets_present,
    rule_low_ret_only,
    rule_positive,
]
