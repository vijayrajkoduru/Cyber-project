# Antivirus / EDR Evasion — Master Reference (`av_evasion_ruff`)

**100% Full Industry Standard catalogue** — modern AV/EDR bypass + Microsoft Defender ATP / CrowdStrike Falcon / SentinelOne evasion + 2024–2026 industry additions.

7 sections, 80 techniques. auto · (probe) · manual · NEW 2024+

---

## Summary

| § | Section | Techniques | Auto | Manual |
|---|---|---|---|---|
| 1 | Detection / Profile / Recon | 10 | 9 | 1 |
| 2 | AMSI Bypass | 10 | 7 | 3 |
| 3 | ETW Bypass | 8 | 5 | 3 |
| 4 | Process Injection / Hollowing | 12 | 8 | 4 |
| 5 | Indirect Syscalls / Hells Gate | 10 | 6 | 4 |
| 6 | Payload Obfuscation / Packing | 10 | 9 | 1 |
| 7 | Modern EDR Bypass (BYOVD, etc.) | 12 | 7 | 5 |
| **TOTAL** | | **72** | **51** | **21** |

---

## §1 — Detection / Profile / Recon
1 AV / EDR product identification · 2 Defender / CrowdStrike / S1 process detect · 3 EDR driver enumeration · 4 ETW provider enumeration · 5 Tamper protection check · 6 Real-time scan toggle · 7 EDR network beacon detection · 8 EDR cloud-callback domain identify · 9 EDRSandblast presence detection · 10 Manual EDR fingerprint refinement

## §2 — AMSI Bypass
11 AMSI patch in-memory (UAS pattern) · 12 AMSI DLL hijack · 13 AMSI provider hijack · 14 PowerShell -EncodedCommand evasion · 15 PowerShell downgrade to v2 · 16 Reflection-based AMSI bypass · 17 Manual creative AMSI bypass · 18 Defender real-time scan toggle · 19 AMSI-aware obfuscator (Invoke-Obfuscation) · 20 Manual creative chain

## §3 — ETW Bypass
21 ETW patch (PatchETW) · 22 ETW provider unhook · 23 EtwTi disable · 24 Manual kernel-mode ETW bypass · 25 ETW user-mode patch via NtTraceEvent · 26 EventLog service stop · 27 Manual creative ETW chain · 28 Manual log evasion

## §4 — Process Injection / Hollowing
29 Classic DLL injection · 30 Reflective DLL injection · 31 Process hollowing · 32 Thread hijack injection · 33 APC injection · 34 Process Doppelgänging · 35 Process Ghosting · 36 Module stomping · 37 Phantom DLL injection · 38 Manual creative injection · 39 Manual unique-primitive injection · 40 Manual EarlyBird APC

## §5 — Indirect Syscalls / Hells Gate NEW
41 Hells Gate syscall stubs · 42 Halos Gate (with EDR-aware fallback) · 43 Tartarus Gate · 44 SysWhispers / SysWhispers3 · 45 Direct syscall via ntdll resolve · 46 Indirect syscall (avoid EDR hooks) · 47 Manual syscall stub generation (assembly) · 48 Manual ntdll unhook · 49 Manual EDR userland hook bypass · 50 Manual creative chain

## §6 — Payload Obfuscation / Packing
51 msfvenom shikata-ga-nai (multi-iter) · 52 Veil-Evasion · 53 Donut (shellcode from .NET/EXE/DLL) · 54 Mythic Apollo / Athena agents · 55 Shellter dynamic injection · 56 UPX packing (then encode) · 57 Custom packer + decode-and-exec · 58 AsyncRAT-style fileless loader · 59 AES + RC4 + multi-stage shellcode · 60 Manual creative obfuscation

## §7 — Modern EDR Bypass (BYOVD, etc.) NEW
61 BYOVD (Bring Your Own Vulnerable Driver) — KDMapper · 62 EDRSandblast kernel-mode kill · 63 TerminateProcess via vulnerable driver · 64 Sliver C2 / Havoc / Mythic agent · 65 EDR-aware Cobalt Strike Malleable C2 · 66 Sleep mask + heap encryption · 67 Hardware breakpoint hooking (HWBP) · 68 NTAPI argument spoofing · 69 Stack-string obfuscation · 70 JIT-compiled payload (no static signature) · 71 Manual creative BYOVD chain · 72 Manual kernel callback bypass

---

## VulnusLab Status
- SOON (module #19) · Planned: Detect AV/EDR, AMSI Bypass, Veil Evasion, Payload Obfuscation
- Coverage: ~0%

## References
- EDRSandblast: https://github.com/wavestone-cdt/EDRSandblast · SysWhispers3: https://github.com/klezVirus/SysWhispers3 · Donut: https://github.com/TheWover/donut · Sliver: https://github.com/BishopFox/sliver · Havoc: https://havocframework.com/ · Mythic: https://github.com/its-a-feature/Mythic
