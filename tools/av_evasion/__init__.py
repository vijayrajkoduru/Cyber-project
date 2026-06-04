"""av_evasion module - EDR / AV detection-capability probes.

Per module_playbooks/20_av_evasion.md - 7 sections, 80 techniques.
Starter set (5 scanners) covers the most widely-instrumented detection
chains an EDR or AV product must catch in 2024-2026:

  tier1_runtime_evasion (§2 AMSI / §3 ETW / §6 Encoded payload):
        amsi_bypass_detection_test
        etw_bypass_detection_test
        encoded_shellcode_detection_test
  tier2_advanced        (§4 Process Injection / §5 Indirect Syscalls):
        process_hollowing_detection_test
        direct_syscall_detection_test

What these probes do (and DO NOT do):
  - Each probe pushes a BENIGN payload over WinRM that exercises a known
    public detection signature (Matt Graeber AMSI bypass, public ETW
    patch, base64 shellcode decode without execute, suspended-process
    +ZwUnmapViewOfSection +ResumeThread call sequence with no shellcode
    written, inline syscall stub for NtAllocateVirtualMemory).
  - None of these probes execute malicious code. The shellcode sled is
    NOPs + xor eax,eax; ret. The process-hollowing target writes the
    original section back. The syscall stub allocates and immediately
    frees memory.
  - The probes assess whether the customer's EDR/AV blocks, alerts, or
    silently lets these textbook offensive primitives pass.

Severity model (this module flips the normal convention):
  HIGH      EDR did NOT detect / block the technique (customer has a gap)
  INFO      Technique ran or was blocked - both are useful telemetry
  POSITIVE  EDR caught the technique cleanly (good signal)

ScanRequest.target = Windows host being audited.
ScanRequest.options carries WinRM creds + per-probe knobs:
  - options.username       (required - WinRM)
  - options.password       (required - WinRM)
  - options.port           (5985 / 5986)
  - options.use_ssl        (bool, default false)
  - options.timeout_sec    (per-WinRM-call cap)

Deferred (covered in playbook, NOT shipped yet):
  - Veil-Evasion (Wine + paid agent)
  - Shellter (Windows-only commercial)
  - Cobalt Strike Malleable C2
  - Sliver / Havoc / Mythic full C2 fan-out
  - BYOVD / EDRSandblast (requires kernel-mode driver upload)
"""
