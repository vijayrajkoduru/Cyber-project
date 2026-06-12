"""hybrid_identity tier4_advisory - honest advisory-by-design coverage.

Enumerates every playbook technique (module_playbooks/28_hybrid_identity.md)
that CANNOT be detected from an external SaaS scanner — because it needs
cloud/host credentials, on-host or LAN execution, a post-compromise foothold,
active exploitation, social engineering, or DoS — and emits each as an
[ADVISORY-BY-DESIGN] INFO finding (vulnerable:false).

This pack performs NO network I/O and NEVER chains into another scanner.
It exists so the report reflects the full 90-technique catalogue without
ever passing a planned severity through as a real finding severity.
"""
