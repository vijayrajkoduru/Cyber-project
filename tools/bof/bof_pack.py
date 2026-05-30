"""§7 Buffer Overflow — 53 endpoints per module_playbooks/07_bof.md.
8 sections: fuzzing, EIP/RIP, bad chars, ROP, shellcode, mitigation bypass,
heap/UAF, modern CET/PAuth bypass.
"""
from tools._pack_common import make_advisory_router

TECHNIQUES = [
    # §1 Fuzzing & Crash Discovery (10)
    ("spike_fuzz_advisory", "SPIKE protocol fuzzer.", "MEDIUM", "5.0"),
    ("boofuzz_advisory", "boofuzz protocol fuzzer.", "MEDIUM", "5.0"),
    ("afl_plus_plus_advisory", "AFL++ instrumented fuzzing.", "MEDIUM", "5.0"),
    ("libfuzzer_advisory", "libFuzzer (LLVM) in-process fuzzing.", "MEDIUM", "5.0"),
    ("honggfuzz_advisory", "honggfuzz coverage-guided fuzzer.", "MEDIUM", "5.0"),
    ("peach_advisory", "Peach fuzzer (legacy).", "MEDIUM", "5.0"),
    ("radamsa_advisory", "Radamsa structure-aware mutation fuzzer.", "MEDIUM", "5.0"),
    ("crash_triage_gdb", "Crash triage via gdb + exploitable plugin.", "MEDIUM", "5.0"),
    ("crash_minimization", "Crash input minimization (afl-tmin / radamsa).", "INFO", "0.0"),
    ("fuzzer_corpus_curation", "Fuzzer corpus curation + seed gen.", "INFO", "0.0"),
    # §2 EIP / RIP Control (8)
    ("pattern_create_offset", "pattern_create / pattern_offset (metasploit).", "INFO", "0.0"),
    ("eip_overwrite_classic", "Classic EIP overwrite on x86.", "HIGH", "8.0"),
    ("rip_overwrite_x64", "RIP overwrite on x86_64.", "HIGH", "8.0"),
    ("seh_overwrite", "SEH chain overwrite (Windows).", "HIGH", "8.0"),
    ("vtable_overwrite", "vtable pointer overwrite.", "HIGH", "8.0"),
    ("got_overwrite", "GOT overwrite (Linux).", "HIGH", "8.0"),
    ("indirect_call_hijack", "Indirect call / jmp hijack.", "HIGH", "8.0"),
    ("partial_overwrite_aslr", "Partial overwrite to bypass ASLR.", "HIGH", "8.0"),
    # §3 Bad Characters (5)
    ("badchars_full_byte_scan", "Bad characters full-byte scan.", "INFO", "0.0"),
    ("badchars_pwntools", "pwntools bad-char identification.", "INFO", "0.0"),
    ("badchars_mona_pyc", "mona.py bad-chars (Immunity).", "INFO", "0.0"),
    ("badchars_charset_alpha", "Alphanumeric-only shellcode encoding.", "MEDIUM", "5.0"),
    ("manual_badchars_test", "Manual bad-char identification (analyst).", "INFO", "0.0"),
    # §4 Return Address / ROP Gadgets (8)
    ("rop_ropper_search", "Ropper ROP gadget search.", "MEDIUM", "5.0"),
    ("rop_ropgadget_search", "ROPgadget search.", "MEDIUM", "5.0"),
    ("rop_one_gadget", "one_gadget (libc) one-shot ROP.", "MEDIUM", "5.0"),
    ("rop_ret2libc", "ret2libc classic ROP chain.", "HIGH", "8.0"),
    ("rop_ret2plt", "ret2plt ROP.", "HIGH", "8.0"),
    ("rop_sigreturn_srop", "SROP (sigreturn-oriented programming).", "HIGH", "8.0"),
    ("rop_jop_jump_oriented", "JOP (jump-oriented programming).", "HIGH", "8.0"),
    ("rop_chain_auto_angrop", "angrop automatic ROP chain.", "MEDIUM", "5.0"),
    # §5 Shellcode Generation (9)
    ("msfvenom_payload", "msfvenom payload generation.", "MEDIUM", "5.5"),
    ("custom_shellcode_asm", "Custom shellcode (assembly).", "MEDIUM", "5.5"),
    ("egghunter_shellcode", "Egghunter shellcode.", "MEDIUM", "5.5"),
    ("alphanumeric_shellcode", "Alphanumeric shellcode (avoiding bad chars).", "MEDIUM", "5.0"),
    ("shellcode_encoder", "Shellcode encoder (shikata, XOR).", "MEDIUM", "5.0"),
    ("polymorphic_shellcode", "Polymorphic shellcode generator.", "MEDIUM", "5.5"),
    ("stage_shellcode_reverse_shell", "Staged reverse shell shellcode.", "HIGH", "7.0"),
    ("stageless_shellcode", "Stageless reverse shell shellcode.", "HIGH", "7.0"),
    ("shellcode_runtime_decoder", "Runtime decoder + exec shellcode.", "MEDIUM", "5.5"),
    # §6 Mitigation Bypass DEP/ASLR/Canary/CFG (6)
    ("dep_bypass_rop_chain", "DEP bypass via ROP chain.", "HIGH", "7.5"),
    ("aslr_bypass_info_leak", "ASLR bypass via info leak.", "HIGH", "7.5"),
    ("stack_canary_leak", "Stack canary leak (master-canary).", "HIGH", "7.5"),
    ("safeseh_bypass", "SafeSEH bypass.", "HIGH", "7.5"),
    ("cfg_bypass_legacy_pointers", "CFG bypass via legacy pointers.", "HIGH", "7.5"),
    ("cet_bypass_research", "Intel CET bypass research ⭐.", "MEDIUM", "5.5"),
    # §7 Heap & UAF (4)
    ("heap_overflow_classic", "Classic heap overflow.", "HIGH", "8.0"),
    ("uaf_use_after_free", "Use-after-free exploit primitive.", "HIGH", "8.0"),
    ("tcache_poisoning", "tcache poisoning (glibc).", "HIGH", "8.0"),
    ("house_of_force", "House of Force heap exploit.", "HIGH", "8.0"),
    # §8 Modern Mitigation Bypass (3) ⭐
    ("pointer_auth_bypass_arm64", "Pointer Authentication (PAC) bypass research ⭐.", "MEDIUM", "5.5"),
    ("mte_bypass_research", "ARM MTE bypass research ⭐.", "MEDIUM", "5.5"),
    ("shadow_stack_bypass", "Intel CET shadow-stack bypass research ⭐.", "MEDIUM", "5.5"),
]

router = make_advisory_router("bof", TECHNIQUES,
    playbook_ref="See module_playbooks/07_bof.md.")


def register(app):
    app.include_router(router)
