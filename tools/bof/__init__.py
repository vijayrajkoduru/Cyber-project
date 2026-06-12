"""bof module - Buffer Overflow / Binary Exploitation static audit.

Per module_playbooks/07_bof.md - 8 sections, 80 techniques.

Static binary-analysis probes (REAL detection - pwntools / capstone /
ROPgadget / pefile + pure-python ELF/PE decoders, no scaffolds):
  - tier1_protections (§6 / §8 Mitigation Audit):
        binary_protection_audit, dangerous_function_detect,
        cfi_modern_mitigation_audit, aslr_textrel_audit
  - tier2_exploit_surface (§2 / §4 / §6 / §7):
        rop_gadget_finder, heap_metadata_audit, format_string_detect,
        seh_overflow_audit

Advisory-by-design (honest INFO; cannot be SaaS-probed - dynamic execution,
live debugger, weaponization, post-compromise, specific silicon):
  - tier3_advisory:
        fuzzing_crash_triage_advisory, exploit_dev_primitive_advisory,
        heap_exploit_advisory, kernel_hw_mitigation_advisory

Customer input: ScanRequest.target = path to a binary on disk (ELF or PE)
that the customer has uploaded.

Concurrency 3 (binary disassembly is CPU heavy; ROPgadget can run minutes
on a 50MB ELF).
"""
