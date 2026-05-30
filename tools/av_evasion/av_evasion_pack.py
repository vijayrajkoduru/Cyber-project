"""§20 AV / EDR Evasion — 72 endpoints under /api/av_evasion/<tool>.

ALL techniques here are post-compromise endpoint-attack primitives that
cannot be probed from outside the customer's perimeter. Rendered as
structured advisories with detection guidance (Sigma rule shape, EDR
rule patterns) so the customer's blue team can validate coverage.
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, wrap_finding

router = APIRouter()


def _adv(tool, target, title, *, sev="MEDIUM", cvss="5.0", cwe="CWE-1395",
         remediation="EDR rule + Sigma coverage; see module_playbooks/20_av_evasion.md.",
         evidence="Advisory — post-compromise EDR-evasion primitive."):
    return {
        "tool": tool, "target": target, "scan_time": 0,
        "vulnerable": sev in ("CRITICAL", "HIGH", "MEDIUM"),
        "severity": sev,
        "findings": [wrap_finding(title, sev, cvss=cvss, cwe=cwe, owasp="A05:2021",
            remediation=remediation, evidence_marker=evidence)],
        "tests_performed": 1, "tests_summary": title[:80], "raw_data": {}
    }


# Table-driven: (slug, title, sev, cvss, remediation_hint)
TECHNIQUES = [
    # §1 Detection / Profile / Recon (10)
    ("av_edr_product_id", "AV/EDR product identification via process / service enum.", "INFO", "0.0", "EDR product hiding (driver name randomization) where supported."),
    ("defender_falcon_s1_proc_detect", "Defender / CrowdStrike Falcon / SentinelOne process detection.", "INFO", "0.0", "Restrict process listing via tokens; AppLocker baseline."),
    ("edr_driver_enum", "EDR kernel-driver enumeration via fltMC.exe / Get-WindowsDriver.", "INFO", "0.0", "Driver-load auditing (Sysmon Event 6); kernel CI policies."),
    ("etw_provider_enum", "ETW provider enumeration via logman / Sealighter.", "INFO", "0.0", "Sigma rule: ETW provider query bursts from non-admin tokens."),
    ("tamper_protection_check", "Tamper Protection check on Defender / EDR.", "MEDIUM", "5.0", "Enforce Tamper Protection cloud-side (Defender for Endpoint)."),
    ("realtime_scan_toggle_check", "Real-time scan toggle detection.", "HIGH", "7.0", "MDE Tamper Protection + EDR-in-block-mode."),
    ("edr_network_beacon_detect", "EDR cloud-callback beacon detection.", "INFO", "0.0", "Allow-list EDR vendor domains; block on egress otherwise."),
    ("edr_cloud_callback_id", "EDR cloud-callback domain identification.", "INFO", "0.0", "DNS/SNI fingerprinting at egress proxy."),
    ("edrsandblast_presence", "⭐ EDRSandblast presence detection.", "HIGH", "7.0", "Sigma: EDRSandblast.exe hash + Pretender behaviors."),
    ("manual_edr_fingerprint", "Manual EDR fingerprint refinement (analyst).", "INFO", "0.0", "See Manual Tests panel."),

    # §2 AMSI Bypass (10)
    ("amsi_patch_inmemory", "⭐ AMSI patch in-memory (UAS pattern).", "HIGH", "7.5", "Sigma: AmsiScanBuffer pattern + invalid amsi.dll hash."),
    ("amsi_dll_hijack", "⭐ AMSI DLL hijack via search-order.", "HIGH", "7.5", "Pin amsi.dll via KnownDlls; deny LoadLibrary from user-writable dirs."),
    ("amsi_provider_hijack", "⭐ AMSI provider hijack via registry CLSID overwrite.", "HIGH", "7.5", "Detect HKLM:\\Software\\Microsoft\\AMSI\\Providers changes."),
    ("ps_encodedcommand_evasion", "PowerShell -EncodedCommand evasion.", "MEDIUM", "5.0", "ScriptBlock Logging (4104) — decode + scan."),
    ("ps_downgrade_v2", "PowerShell downgrade to v2 (no AMSI).", "HIGH", "7.0", "Uninstall PowerShell v2 feature; alert on -Version 2 flag."),
    ("amsi_reflection_bypass", "Reflection-based AMSI bypass.", "HIGH", "7.0", "ScriptBlock Logging + AMSI provider audit."),
    ("manual_amsi_bypass", "Manual creative AMSI bypass (analyst).", "INFO", "0.0", "See Manual Tests panel."),
    ("defender_realtime_toggle_manual", "⭐ Defender real-time scan toggle (manual).", "INFO", "0.0", "Tamper Protection blocks Set-MpPreference."),
    ("invoke_obfuscation", "⭐ AMSI-aware obfuscator (Invoke-Obfuscation).", "MEDIUM", "5.5", "ScriptBlock entropy detection (Sigma)."),
    ("manual_amsi_chain", "Manual creative AMSI chain.", "INFO", "0.0", "See Manual Tests panel."),

    # §3 ETW Bypass (8)
    ("etw_patch_patchetw", "⭐ ETW patch (PatchETW.exe).", "HIGH", "7.5", "Detect NtTraceControl from non-admin; kernel CI policy."),
    ("etw_provider_unhook", "⭐ ETW provider unhook via EventWriteFull patch.", "HIGH", "7.5", "Kernel callback verification (Sysmon driver)."),
    ("etwti_disable", "EtwTi (threat-intel ETW) disable.", "HIGH", "7.5", "EtwTi tampering alert (Sysmon)."),
    ("manual_kernel_etw_bypass", "⭐ Manual kernel-mode ETW bypass (analyst).", "INFO", "0.0", "See Manual Tests."),
    ("etw_usermode_patch_nt_trace_event", "⭐ ETW user-mode patch via NtTraceEvent stub.", "HIGH", "7.5", "ScriptBlock Logging + memory integrity."),
    ("eventlog_service_stop", "EventLog service stop.", "HIGH", "7.0", "EventLog service hardening; Sysmon picks up service stop."),
    ("manual_etw_chain", "Manual creative ETW chain.", "INFO", "0.0", "See Manual Tests panel."),
    ("manual_log_evasion", "Manual log evasion (analyst).", "INFO", "0.0", "See Manual Tests."),

    # §4 Process Injection / Hollowing (12)
    ("classic_dll_injection", "Classic DLL injection via LoadLibrary.", "HIGH", "7.0", "Sysmon Event 7 (image loaded) anomalies."),
    ("reflective_dll_injection", "Reflective DLL injection (no LoadLibrary).", "HIGH", "7.5", "Memory scan for MZ headers in non-image regions."),
    ("process_hollowing", "Process hollowing.", "HIGH", "7.5", "Sysmon Event 8 CreateRemoteThread + WriteProcessMemory."),
    ("thread_hijack", "Thread hijack injection.", "HIGH", "7.5", "ETW SuspendThread+SetContext+ResumeThread anomaly."),
    ("apc_injection", "APC injection (QueueUserAPC).", "HIGH", "7.0", "ETW QueueUserAPC anomaly."),
    ("process_doppelganging", "⭐ Process Doppelgänging (transactional NTFS).", "HIGH", "7.5", "NTFS transaction creation auditing."),
    ("process_ghosting", "⭐ Process Ghosting.", "HIGH", "7.5", "Image-section creation anomaly detection."),
    ("module_stomping", "⭐ Module stomping.", "HIGH", "7.5", "Memory integrity check for mapped images."),
    ("phantom_dll_injection", "⭐ Phantom DLL injection.", "HIGH", "7.5", "Image-load callback anomaly."),
    ("manual_creative_injection", "Manual creative injection (analyst).", "INFO", "0.0", "See Manual Tests."),
    ("manual_unique_primitive_injection", "Manual unique-primitive injection.", "INFO", "0.0", "See Manual Tests."),
    ("manual_earlybird_apc", "Manual EarlyBird APC.", "INFO", "0.0", "See Manual Tests."),

    # §5 Indirect Syscalls / Hells Gate (10) ⭐
    ("hells_gate_syscall_stubs", "⭐ Hells Gate syscall stubs.", "HIGH", "7.5", "ntdll integrity check; userland hook integrity."),
    ("halos_gate_fallback", "⭐ Halos Gate (EDR-aware fallback).", "HIGH", "7.5", "Same as Hells Gate + ETW-Ti."),
    ("tartarus_gate", "⭐ Tartarus Gate.", "HIGH", "7.5", "Same as above."),
    ("syswhispers3", "⭐ SysWhispers / SysWhispers3.", "HIGH", "7.5", "Static signature on syscall stubs."),
    ("direct_syscall_ntdll", "⭐ Direct syscall via ntdll resolve.", "HIGH", "7.5", "Userland hook integrity (Frida-style audit)."),
    ("indirect_syscall_no_hooks", "⭐ Indirect syscall (avoid EDR hooks).", "HIGH", "7.5", "Kernel-mode ETW-Ti coverage."),
    ("manual_syscall_stubgen", "⭐ Manual syscall stub generation (analyst, assembly).", "INFO", "0.0", "See Manual Tests."),
    ("manual_ntdll_unhook", "⭐ Manual ntdll unhook.", "INFO", "0.0", "See Manual Tests."),
    ("manual_edr_userland_hook_bypass", "⭐ Manual EDR userland hook bypass.", "INFO", "0.0", "See Manual Tests."),
    ("manual_creative_chain_5", "⭐ Manual creative chain.", "INFO", "0.0", "See Manual Tests."),

    # §6 Payload Obfuscation / Packing (10)
    ("msfvenom_shikata", "msfvenom shikata-ga-nai multi-iter encoding.", "MEDIUM", "5.5", "YARA: msfvenom shellcode patterns."),
    ("veil_evasion", "Veil-Evasion payload generation.", "MEDIUM", "5.5", "AV signature on Veil templates."),
    ("donut_shellcode", "⭐ Donut (shellcode from .NET/EXE/DLL).", "HIGH", "7.0", "YARA: Donut loader signature."),
    ("mythic_apollo_athena", "⭐ Mythic Apollo / Athena agents.", "HIGH", "7.5", "Sigma: HTTP/2 + Mythic profiles."),
    ("shellter_dynamic", "Shellter dynamic injection.", "MEDIUM", "5.5", "YARA: Shellter signature in PE imports."),
    ("upx_then_encode", "UPX packing + encoder.", "LOW", "3.0", "UPX detection in EDR."),
    ("custom_packer", "Custom packer + decode-and-exec.", "MEDIUM", "5.5", "Behavioral: unpacking pattern in EDR."),
    ("asyncrat_fileless", "⭐ AsyncRAT-style fileless loader.", "HIGH", "7.5", "Memory-only execution detection."),
    ("aes_rc4_multistage", "⭐ AES + RC4 + multi-stage shellcode.", "HIGH", "7.0", "JA3/JA4 fingerprint of staged-payload TLS."),
    ("manual_creative_obfuscation", "Manual creative obfuscation (analyst).", "INFO", "0.0", "See Manual Tests."),

    # §7 Modern EDR Bypass / BYOVD (12) ⭐
    ("byovd_kdmapper", "⭐ BYOVD via KDMapper (loadable vulnerable driver).", "CRITICAL", "9.0", "WDAC code-integrity policy; vulnerable-driver block-list (HVCI)."),
    ("edrsandblast_kernel_kill", "⭐ EDRSandblast kernel-mode EDR kill.", "CRITICAL", "9.0", "HVCI + Microsoft vulnerable driver block-list (2023+)."),
    ("terminateprocess_via_vuln_driver", "⭐ TerminateProcess via vulnerable driver.", "CRITICAL", "9.0", "Same as above."),
    ("sliver_havoc_mythic_agent", "⭐ Sliver C2 / Havoc / Mythic agent.", "HIGH", "7.5", "C2 framework JA3 / SSL CN fingerprints."),
    ("cs_malleable_c2_profile", "⭐ EDR-aware Cobalt Strike Malleable C2.", "HIGH", "7.5", "Profile sleep-mask + URI patterns."),
    ("sleep_mask_heap_encryption", "⭐ Sleep mask + heap encryption.", "HIGH", "7.0", "Periodic heap-integrity audit (Beacon hunting)."),
    ("hwbp_hooking", "⭐ Hardware breakpoint (HWBP) hooking.", "HIGH", "7.5", "DR registers anomaly detection (ETW-Ti)."),
    ("ntapi_arg_spoofing", "⭐ NTAPI argument spoofing.", "HIGH", "7.0", "Kernel callback inspection of stack frames."),
    ("stack_string_obfuscation", "⭐ Stack-string obfuscation.", "MEDIUM", "5.0", "Behavioral analytics rather than static."),
    ("jit_payload_no_signature", "⭐ JIT-compiled payload (no static signature).", "HIGH", "7.5", "Behavioral: high-allocation pattern + RWX."),
    ("manual_byovd_chain", "⭐ Manual creative BYOVD chain.", "INFO", "0.0", "See Manual Tests."),
    ("manual_kernel_callback_bypass", "⭐ Manual kernel callback bypass.", "INFO", "0.0", "See Manual Tests."),
]


def _make_handler(slug, title, sev, cvss, remed):
    def _h(req: ScanRequest, _=Depends(verify_scan_quota)):
        return _adv(slug, req.target, title, sev=sev, cvss=cvss, remediation=remed)
    _h.__name__ = slug
    return _h


for slug, title, sev, cvss, remed in TECHNIQUES:
    router.add_api_route(f"/api/av_evasion/{slug}", _make_handler(slug, title, sev, cvss, remed),
                          methods=["POST"])


def register(app):
    app.include_router(router)
