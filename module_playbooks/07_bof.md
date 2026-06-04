# Buffer Overflow — Master Reference (`bof_ruff`)

**100% Full Industry Standard catalogue** — aligned with OSCP-style 7-phase BOF + corelan.be canon + pwntools methodology + 2024–2026 modern mitigation bypass.

8 sections, 80 techniques.

**Legend:** auto · (probe) · manual · NEW 2024+

---

## Summary

| § | Section | Techniques | Auto | Manual |
|---|---|---|---|---|
| 1 | Fuzzing & Crash Discovery | 12 | 10 | 2 |
| 2 | EIP / RIP Control | 10 | 8 | 2 |
| 3 | Bad Characters Identification | 6 | 5 | 1 |
| 4 | Return Address / ROP Gadgets | 10 | 8 | 2 |
| 5 | Shellcode Generation | 10 | 9 | 1 |
| 6 | Mitigation Bypass (DEP / ASLR / Canary / CFG) | 12 | 6 | 6 |
| 7 | Heap & UAF Exploitation | 10 | 4 | 6 |
| 8 | Modern Mitigation Bypass (CET / Pointer Auth) | 10 | 3 | 7 |
| **TOTAL** | | **80** | **53** | **27** |

---

## §1 — Fuzzing & Crash Discovery

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 1 | Network protocol fuzzing | boofuzz | |
| 2 | File format fuzzing | AFL++, honggfuzz | |
| 3 | Command-line argument fuzzing | radamsa + custom | |
| 4 | Stateful fuzzing (LibAFL) | LibAFL | |
| 5 | Coverage-guided fuzzing | AFL++ | |
| 6 | Grammar-based fuzzing | Grammarinator | |
| 7 | Crash deduplication | exploitable / casr | |
| 8 | Crash triage (severity scoring) | exploitable, casr | |
| 9 | Auto crash analysis | gdb + custom | |
| 10 | Generic crash collector | custom + corefiles | |
| 11 | Manual creative fuzz target selection | analyst | |
| 12 | Manual crash interpretation | analyst | |

---

## §2 — EIP / RIP Control

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 13 | Cyclic pattern generation | pattern_create, pwntools cyclic | |
| 14 | Offset calculation | pattern_offset, cyclic_find | |
| 15 | EIP overwrite verification | debugger + custom | |
| 16 | Stack alignment check | debugger | |
| 17 | Saved return address tracking | debugger | |
| 18 | SEH overwrite (32-bit Windows) | Mona.py + custom | |
| 19 | Egghunter requirement detection | manual + custom | |
| 20 | Limited buffer space analysis | manual + custom | |
| 21 | Manual exploit primitive selection | analyst | |
| 22 | Manual SEH chain analysis | analyst | |

---

## §3 — Bad Characters Identification

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 23 | Generate all-byte string | custom + pwntools | |
| 24 | Compare in-memory vs sent | mona.py compare | |
| 25 | Iterative bad-char filtering | custom + scripted | |
| 26 | Protocol-specific bad-char map | custom | |
| 27 | Unicode-safe alternative encoding | manual + custom | |
| 28 | Manual edge-case bad-char analysis | analyst | |

---

## §4 — Return Address / ROP Gadgets

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 29 | ROP gadget search (ROPgadget) | ROPgadget | |
| 30 | ROP gadget search (ropper) | ropper | |
| 31 | ROP chain auto-build | pwntools rop.find_gadget | |
| 32 | mona.py jmp esp / pop pop ret | mona.py jmp | |
| 33 | Non-ASLR module identification | mona.py modules | |
| 34 | DLL-based return address (PIE bypass) | mona.py + custom | |
| 35 | Stack pivot gadget find | ROPgadget | |
| 36 | sigreturn-oriented programming (SROP) | pwntools SigreturnFrame | |
| 37 | Manual ROP chain refinement | analyst | |
| 38 | Manual stack alignment fix-up | analyst | |

---

## §5 — Shellcode Generation

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 39 | Reverse shell (msfvenom) | msfvenom | |
| 40 | Bind shell shellcode | msfvenom | |
| 41 | Custom shellcode (pwntools shellcraft) | pwntools shellcraft | |
| 42 | Encoder (msfvenom shikata-ga-nai) | msfvenom -e | |
| 43 | Multi-stage shellcode (egghunter + final) | msfvenom + custom | |
| 44 | Position-independent shellcode | nasm + custom | |
| 45 | Shellcode size optimization | manual + nasm | |
| 46 | Unicode-safe shellcode | venetian shellcode | |
| 47 | Shellcode obfuscation (AMSI bypass aware) | custom + msfvenom | |
| 48 | Manual creative shellcode writing | analyst + nasm | |

---

## §6 — Mitigation Bypass (DEP / ASLR / Canary / CFG)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 49 | DEP bypass via ROP chain | pwntools + ROPgadget | |
| 50 | ret2libc / ret2plt | pwntools + manual | |
| 51 | Stack canary leak (format string / read primitive) | manual | |
| 52 | Stack canary brute force (fork-server) | manual + custom | |
| 53 | ASLR bypass via info leak | manual + custom | |
| 54 | ASLR bypass via partial overwrite | manual | |
| 55 | PIE bypass via leak | manual + custom | |
| 56 | CFG bypass (Windows) | manual + research | |
| 57 | Win 11 modern mitigations check | custom + nmap | |
| 58 | RELRO partial → full lazy-binding abuse | manual | |
| 59 | Stack-cookie XOR-with-fs:[0] leak (Linux) | manual + custom | |
| 60 | KASLR bypass (kernel) | manual + research | |

---

## §7 — Heap & UAF Exploitation

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 61 | Heap spray | pwntools + custom | |
| 62 | tcache poisoning (glibc 2.27+) | pwntools + manual | |
| 63 | fastbin attack | manual + research | |
| 64 | UAF (Use-After-Free) | manual + research | |
| 65 | Double-free | manual + research | |
| 66 | House of Force / Spirit / Orange / Einherjar | manual + research | |
| 67 | Type confusion exploit | manual | |
| 68 | Modern glibc 2.34+ tcache + safe-linking bypass | manual + research | |
| 69 | Manual heap layout / Feng Shui | analyst | |
| 70 | Manual chained heap exploit | analyst | |

---

## §8 — Modern Mitigation Bypass NEW (2024+)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 71 | Intel CET (Control-flow Enforcement) audit | custom + ELF | |
| 72 | ARM Pointer Authentication (PAC) audit | custom + binary | |
| 73 | ARM MTE (Memory Tagging Extension) audit | custom + binary | |
| 74 | Linux IBT (Indirect Branch Tracking) audit | custom + ELF | |
| 75 | Shadow Stack (CET-SS) bypass | manual + research | |
| 76 | Win 11 ARM64EC mitigation bypass | manual + research | |
| 77 | macOS pointer-auth bypass | manual + research | |
| 78 | iOS PAC bypass (CryptoLib) | manual + research | |
| 79 | Hypervisor escape (KVM, Hyper-V CVE) | manual + research | |
| 80 | TEE / SGX / TrustZone enclave bypass | manual + research | |

---

## Compliance Mapping
- **OSCP / OSCE methodology** · **PTES Exploitation phase** · **NIST SP 800-115 §4.4**

## VulnusLab BOF Status
- Status: LIVE (7-phase OSCP flow: fuzz → offset → eip → badchars → jmpesp → shellcode → exploit)
- Estimated coverage: ~30% of full standard

## Roadmap to 100%
1. Phase B-1: §1 fuzzing pack (12 scanners — wrap boofuzz/AFL++)
2. Phase B-2: §2–§5 expand existing 7-phase to full toolkit
3. Phase B-3: §6 mitigation bypass detection (12)
4. Phase B-4: §7 heap exploit primitives (10, mostly probe)
5. Phase B-5: §8 modern mitigation audit (10 )

## References
- corelan.be tutorials: https://www.corelan.be/index.php/articles/
- pwntools: https://docs.pwntools.com/
- mona.py: https://github.com/corelan/mona
- AFL++: https://aflplus.plus/
- LibAFL: https://github.com/AFLplusplus/LibAFL
- ROPgadget: https://github.com/JonathanSalwan/ROPgadget
- boofuzz: https://github.com/jtpereyda/boofuzz
- exploit-db: https://www.exploit-db.com/
