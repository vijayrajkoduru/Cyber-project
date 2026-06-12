"""tier3_advisory - honest [ADVISORY-BY-DESIGN] INFO scanners.

The playbook techniques in this tier CANNOT be performed by an external
detection-only SaaS against an uploaded binary, because they require one or
more of: a live debugger / running target process, dynamic crash reproduction,
weaponized payload generation (shellcode / ROP chains), an interactive
fork-server, LAN adjacency, a post-compromise foothold, or destructive /
DoS-adjacent execution. VulnusLab is VA (find weaknesses) not PT (exploit), so
these are emitted as a single honest INFO each, with the full manual procedure
and defensive guidance in the remediation. They are NOT forge gaps and NEVER
fabricate a graded severity.

  - fuzzing_crash_triage_advisory : §1 fuzzing + crash dedup/triage (dynamic)
  - exploit_dev_primitive_advisory: §2/§3/§4/§5 offset/badchar/EIP/ROP/shellcode
  - heap_exploit_advisory         : §7 heap / UAF / tcache / House-of (dynamic)
  - kernel_hw_mitigation_advisory : §6 #60 KASLR + §8 #75-80 PAC/MTE/hypervisor/TEE
"""
