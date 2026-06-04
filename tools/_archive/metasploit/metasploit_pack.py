"""§11 Metasploit — 67 endpoints per 11_metasploit.md.
8 sections: auxiliary, exploit modules, payloads, post-exploit, encoders,
db, meterpreter, modern msfvenom evasion.
"""
from tools._pack_common import make_advisory_router

TECHNIQUES = [
    # §1 Auxiliary Modules (10)
    ("aux_scanner_portscan_tcp", "auxiliary/scanner/portscan/tcp.", "MEDIUM", "5.0"),
    ("aux_scanner_smb_version", "auxiliary/scanner/smb/smb_version.", "MEDIUM", "5.0"),
    ("aux_scanner_ssh_version", "auxiliary/scanner/ssh/ssh_version.", "MEDIUM", "5.0"),
    ("aux_scanner_http_version", "auxiliary/scanner/http/http_version.", "MEDIUM", "5.0"),
    ("aux_scanner_dns_amplification", "auxiliary/scanner/dns/dns_amp.", "MEDIUM", "5.0"),
    ("aux_scanner_snmp_login", "auxiliary/scanner/snmp/snmp_login.", "HIGH", "7.0"),
    ("aux_scanner_ftp_anonymous", "auxiliary/scanner/ftp/anonymous.", "HIGH", "7.0"),
    ("aux_scanner_telnet_login", "auxiliary/scanner/telnet/telnet_login.", "HIGH", "7.0"),
    ("aux_scanner_rdp_ms12_020", "auxiliary/scanner/rdp/ms12_020_check.", "HIGH", "8.0"),
    ("aux_scanner_smb_ms17_010", "auxiliary/scanner/smb/smb_ms17_010.", "CRITICAL", "9.3"),
    # §2 Exploit Modules (11)
    ("exploit_multi_handler", "exploit/multi/handler.", "INFO", "0.0"),
    ("exploit_windows_smb_ms17_010", "exploit/windows/smb/ms17_010_eternalblue.", "CRITICAL", "9.3"),
    ("exploit_windows_smb_psexec", "exploit/windows/smb/psexec.", "HIGH", "7.5"),
    ("exploit_multi_http_struts2", "exploit/multi/http/struts2_*.", "CRITICAL", "9.8"),
    ("exploit_linux_local_dirty_pipe", "exploit/linux/local/dirty_pipe.", "HIGH", "7.8"),
    ("exploit_unix_ftp_vsftpd_234_bd", "exploit/unix/ftp/vsftpd_234_backdoor.", "CRITICAL", "10.0"),
    ("exploit_windows_dcerpc_ms08_067", "exploit/windows/smb/ms08_067_netapi.", "CRITICAL", "10.0"),
    ("exploit_multi_http_log4shell", "exploit/multi/http/log4j_*.", "CRITICAL", "9.8"),
    ("exploit_multi_http_spring4shell", "exploit/multi/http/spring_*.", "CRITICAL", "9.8"),
    ("exploit_windows_local_uac_bypass", "exploit/windows/local/bypass_uac.", "HIGH", "7.5"),
    ("manual_exploit_module_select", "Manual exploit module selection.", "INFO", "0.0"),
    # §3 Payloads (9)
    ("payload_windows_meterpreter_reverse_tcp", "payload windows/meterpreter/reverse_tcp.", "HIGH", "7.5"),
    ("payload_windows_meterpreter_reverse_https", "payload windows/meterpreter/reverse_https.", "HIGH", "7.5"),
    ("payload_linux_x86_meterpreter_reverse_tcp", "payload linux/x86/meterpreter/reverse_tcp.", "HIGH", "7.5"),
    ("payload_linux_x64_meterpreter_reverse_tcp", "payload linux/x64/meterpreter/reverse_tcp.", "HIGH", "7.5"),
    ("payload_python_meterpreter_reverse_tcp", "payload python/meterpreter/reverse_tcp.", "HIGH", "7.5"),
    ("payload_php_meterpreter_reverse_tcp", "payload php/meterpreter/reverse_tcp.", "HIGH", "7.5"),
    ("payload_windows_shell_reverse_tcp", "payload windows/shell/reverse_tcp.", "HIGH", "7.0"),
    ("payload_cmd_unix_reverse_bash", "payload cmd/unix/reverse_bash.", "HIGH", "7.0"),
    ("payload_java_meterpreter_reverse_tcp", "payload java/meterpreter/reverse_tcp.", "HIGH", "7.5"),
    # §4 Post-Exploit Modules (10)
    ("post_multi_recon_local_exploit_suggester", "post/multi/recon/local_exploit_suggester.", "MEDIUM", "5.5"),
    ("post_windows_gather_hashdump", "post/windows/gather/hashdump.", "CRITICAL", "9.0"),
    ("post_windows_gather_credentials_browser", "post/windows/gather/credentials/*.", "HIGH", "8.0"),
    ("post_windows_gather_enum_av", "post/windows/gather/enum_av_excluded.", "MEDIUM", "5.0"),
    ("post_windows_gather_enum_chrome", "post/windows/gather/enum_chrome.", "HIGH", "7.5"),
    ("post_windows_gather_enum_putty_saved_sessions", "post/windows/gather/enum_putty.", "HIGH", "7.5"),
    ("post_linux_gather_enum_system", "post/linux/gather/enum_system.", "INFO", "0.0"),
    ("post_linux_gather_hashdump", "post/linux/gather/hashdump.", "CRITICAL", "9.0"),
    ("post_multi_gather_ssh_creds", "post/multi/gather/ssh_creds.", "HIGH", "8.0"),
    ("post_multi_gather_aws_keys", "post/multi/gather/aws_keys.", "CRITICAL", "9.0"),
    # §5 Encoders / Evasion (6)
    ("encoder_x86_shikata_ga_nai", "encoder x86/shikata_ga_nai.", "MEDIUM", "5.0"),
    ("encoder_x86_xor_dynamic", "encoder x86/xor_dynamic.", "MEDIUM", "5.0"),
    ("encoder_cmd_powershell_base64", "encoder cmd/powershell_base64.", "MEDIUM", "5.0"),
    ("encoder_cmd_unix_perl", "encoder cmd/unix/perl.", "MEDIUM", "5.0"),
    ("encoder_x64_xor", "encoder x64/xor.", "MEDIUM", "5.0"),
    ("encoder_x86_alpha_mixed", "encoder x86/alpha_mixed.", "MEDIUM", "5.0"),
    # §6 Database Integration (6)
    ("msf_db_postgres_init", "msf db_connect to PostgreSQL.", "INFO", "0.0"),
    ("msf_db_nmap_import", "msf db_nmap import.", "INFO", "0.0"),
    ("msf_db_workspace_setup", "msf workspace management.", "INFO", "0.0"),
    ("msf_db_creds_management", "msf creds add/list management.", "INFO", "0.0"),
    ("msf_db_loot_management", "msf loot collection.", "INFO", "0.0"),
    ("msf_db_notes_management", "msf notes management.", "INFO", "0.0"),
    # §7 Meterpreter Operations (10)
    ("meterpreter_sysinfo", "meterpreter sysinfo.", "INFO", "0.0"),
    ("meterpreter_getuid", "meterpreter getuid + getsystem.", "HIGH", "8.0"),
    ("meterpreter_hashdump", "meterpreter hashdump.", "CRITICAL", "9.0"),
    ("meterpreter_screenshot", "meterpreter screenshot.", "MEDIUM", "5.5"),
    ("meterpreter_keylog", "meterpreter keyscan_start.", "HIGH", "7.5"),
    ("meterpreter_webcam_snap", "meterpreter webcam_snap.", "HIGH", "7.0"),
    ("meterpreter_persistence", "meterpreter persistence run.", "HIGH", "7.5"),
    ("meterpreter_route_portfwd", "meterpreter route add + portfwd.", "HIGH", "7.5"),
    ("meterpreter_migrate", "meterpreter migrate.", "MEDIUM", "5.5"),
    ("meterpreter_clear_eventlog", "meterpreter clearev.", "HIGH", "7.0"),
    # §8 Modern AV/EDR Evasion (5)
    ("msfvenom_donut_advisory", "msfvenom + Donut shellcode loader.", "HIGH", "7.5"),
    ("msfvenom_sliver_advisory", "msfvenom → Sliver C2 transition.", "HIGH", "7.5"),
    ("msfvenom_havoc_advisory", "msfvenom → Havoc framework.", "HIGH", "7.5"),
    ("msfvenom_polymorphic_pe", "msfvenom polymorphic PE generation.", "HIGH", "7.0"),
    ("msfvenom_with_obfuscator_advisory", "msfvenom + Invoke-Obfuscation chain.", "HIGH", "7.0"),
]

router = make_advisory_router("metasploit", TECHNIQUES,
    playbook_ref="See module_playbooks/11_metasploit.md.")


def register(app):
    app.include_router(router)
