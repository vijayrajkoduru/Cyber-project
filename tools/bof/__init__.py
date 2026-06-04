"""bof module - Buffer Overflow / Binary Exploitation static audit.

Per module_playbooks/07_bof.md - 8 sections, 80 techniques.
Starter set (5 scanners) covers the highest-impact playbook items:
  - tier1_protections   (§6 Mitigation Audit):
        binary_protection_audit, dangerous_function_detect
  - tier2_exploit_surface (§4 ROP / §7 Heap / §6 Format-String):
        rop_gadget_finder, heap_metadata_audit, format_string_detect

Customer input: ScanRequest.target = path to a binary on disk (ELF or PE)
that the customer has uploaded.  All probes use real pwntools / capstone /
ROPgadget / pefile subprocess calls - no scaffolds.

Concurrency 3 (binary disassembly is CPU heavy; ROPgadget can run minutes
on a 50MB ELF).  More scanners (boofuzz/AFL++, ret2libc auto-rop, CET/PAC
audit, heap house-of-* primitives) will be added per playbook section.
"""
