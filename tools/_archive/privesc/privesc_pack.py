"""§12 PrivEsc — 78 endpoints per 12_privesc.md.
7 sections: Linux/Windows/macOS enum, sudo/SUID/caps, service/cron, kernel CVE,
container/cloud privesc.
"""
from tools._pack_common import make_advisory_router

TECHNIQUES = [
    # §1 Linux Enumeration (17)
    ("linpeas", "LinPEAS.", "MEDIUM", "5.0"),
    ("linenum", "LinEnum.", "MEDIUM", "5.0"),
    ("linux_smart_enum", "linux-smart-enumeration.", "MEDIUM", "5.0"),
    ("lse", "Linux Exploit Suggester (LSE).", "MEDIUM", "5.0"),
    ("linux_exploit_suggester_2", "linux-exploit-suggester-2.", "MEDIUM", "5.0"),
    ("unix_privesc_check", "unix-privesc-check.", "MEDIUM", "5.0"),
    ("pspy", "pspy (process spy).", "MEDIUM", "5.0"),
    ("env_var_dump", "Environment variable dump.", "INFO", "0.0"),
    ("etc_passwd_writable", "/etc/passwd writable check.", "CRITICAL", "9.0"),
    ("home_ssh_writable", "Home .ssh writable check.", "HIGH", "7.5"),
    ("cron_writable_check", "Cron job writable check.", "HIGH", "7.5"),
    ("path_writable_check", "PATH writable directories.", "HIGH", "7.0"),
    ("ld_library_path_check", "LD_LIBRARY_PATH abuse check.", "HIGH", "7.0"),
    ("logrotate_writable", "logrotate writable config.", "HIGH", "7.0"),
    ("kernel_version_id", "Kernel version + exploit suggester.", "INFO", "0.0"),
    ("docker_present_check", "Docker daemon presence check.", "MEDIUM", "5.5"),
    ("snap_lxd_check", "Snap/LXD privesc check.", "HIGH", "7.5"),
    # §2 Windows Enumeration (17)
    ("winpeas_full", "WinPEAS full enumeration.", "MEDIUM", "5.0"),
    ("powerup", "PowerUp.", "MEDIUM", "5.0"),
    ("seatbelt", "Seatbelt.", "MEDIUM", "5.0"),
    ("watson", "Watson.", "MEDIUM", "5.0"),
    ("windows_exploit_suggester", "windows-exploit-suggester.", "MEDIUM", "5.0"),
    ("sherlock", "Sherlock (PowerShell).", "MEDIUM", "5.0"),
    ("jaws", "JAWS (JustAnotherWindowsScript).", "MEDIUM", "5.0"),
    ("accesschk_writable_services", "accesschk writable services.", "HIGH", "7.5"),
    ("alwaysinstallelevated", "AlwaysInstallElevated registry check.", "HIGH", "7.5"),
    ("unquoted_service_paths", "Unquoted service paths.", "HIGH", "7.5"),
    ("writable_service_binaries", "Writable service binaries.", "HIGH", "8.0"),
    ("scheduledtasks_writable", "Scheduled tasks writable.", "HIGH", "7.5"),
    ("autoruns_registry_writable", "Autoruns registry writable.", "HIGH", "7.5"),
    ("token_impersonation_seimpersonate", "SeImpersonatePrivilege check (potato chain).", "HIGH", "8.0"),
    ("token_impersonation_seassign", "SeAssignPrimaryTokenPrivilege.", "HIGH", "8.0"),
    ("uac_bypass_audit", "UAC bypass technique audit.", "HIGH", "7.5"),
    ("dll_hijack_search_order_check", "DLL hijack search-order check.", "HIGH", "7.5"),
    # §3 macOS Enumeration (8)
    ("macpeas", "MacPEAS.", "MEDIUM", "5.0"),
    ("macos_kc_dump_check", "macOS keychain dump check.", "HIGH", "7.5"),
    ("macos_tcc_check", "macOS TCC permission audit.", "HIGH", "7.0"),
    ("macos_xpc_audit", "macOS XPC service audit.", "HIGH", "7.5"),
    ("macos_authd_audit", "macOS authd audit.", "MEDIUM", "5.5"),
    ("macos_launchd_audit", "macOS launchd audit.", "MEDIUM", "5.5"),
    ("macos_csrutil_status", "macOS csrutil status (SIP audit).", "INFO", "0.0"),
    ("macos_admin_group_check", "macOS admin group check.", "INFO", "0.0"),
    # §4 Sudo / SUID / Caps Abuse (11)
    ("gtfobins_suid", "GTFOBins SUID search.", "HIGH", "7.5"),
    ("gtfobins_sudo", "GTFOBins sudo search.", "HIGH", "7.5"),
    ("gtfobins_caps", "GTFOBins capabilities search.", "HIGH", "7.5"),
    ("sudo_baron_samedit", "Baron Samedit (CVE-2021-3156).", "CRITICAL", "7.8"),
    ("sudo_token_reuse_check", "sudo token reuse check.", "HIGH", "7.5"),
    ("suid_nmap_old", "SUID nmap legacy.", "HIGH", "7.5"),
    ("suid_vim_check", "SUID vim check.", "HIGH", "7.5"),
    ("suid_perl_python_ruby", "SUID perl/python/ruby check.", "HIGH", "7.5"),
    ("cap_setuid_check", "CAP_SETUID check.", "HIGH", "7.5"),
    ("cap_sys_admin_check", "CAP_SYS_ADMIN check.", "HIGH", "8.0"),
    ("manual_sudo_suid_review", "Manual sudo/SUID review (analyst).", "INFO", "0.0"),
    # §5 Service / Cron / Scheduled Abuse (9)
    ("cron_writable_jobs", "Writable cron job files.", "HIGH", "7.5"),
    ("cron_root_world_writable", "World-writable root cron scripts.", "CRITICAL", "9.0"),
    ("systemd_writable_unit", "Writable systemd unit file.", "HIGH", "7.5"),
    ("systemd_overridden_service", "systemd overridden service.", "HIGH", "7.0"),
    ("init_d_writable_script", "/etc/init.d/ writable script.", "HIGH", "7.5"),
    ("anacron_writable_job", "anacron writable job.", "HIGH", "7.5"),
    ("scheduled_task_writable_xml", "Windows scheduled task XML writable.", "HIGH", "7.5"),
    ("at_jobs_writable", "at jobs writable.", "HIGH", "7.0"),
    ("services_msc_writable", "services.msc writable services (Windows).", "HIGH", "8.0"),
    # §6 Kernel CVE Match (9)
    ("kernel_cve_dirty_pipe", "Dirty Pipe (CVE-2022-0847).", "HIGH", "7.8"),
    ("kernel_cve_pwnkit", "PwnKit (CVE-2021-4034).", "HIGH", "7.8"),
    ("kernel_cve_dirtycow", "Dirty COW (CVE-2016-5195).", "CRITICAL", "7.8"),
    ("kernel_cve_overlayfs", "OverlayFS (CVE-2021-3493).", "HIGH", "7.8"),
    ("kernel_cve_netfilter", "netfilter (CVE-2023-32233).", "HIGH", "7.8"),
    ("kernel_cve_io_uring", "io_uring (CVE-2022-29582).", "HIGH", "7.8"),
    ("kernel_cve_printnightmare", "PrintNightmare (CVE-2021-34527).", "CRITICAL", "8.8"),
    ("kernel_cve_hivenightmare", "HiveNightmare (CVE-2021-36934).", "HIGH", "7.8"),
    ("kernel_cve_clfs_2024_38193", "Windows CLFS (CVE-2024-38193) .", "HIGH", "7.8"),
    # §7 Container / Cloud PrivEsc (7)
    ("container_escape_docker_sock", "Container escape via docker.sock.", "CRITICAL", "9.5"),
    ("container_escape_capsysadmin", "Container escape via CAP_SYS_ADMIN.", "HIGH", "8.0"),
    ("container_escape_leaky_vessels", "Leaky Vessels runc escape (CVE-2024-21626).", "HIGH", "8.6"),
    ("k8s_pod_to_node_privesc", "K8s pod → node privesc.", "HIGH", "8.0"),
    ("aws_iam_privesc_paths", "AWS IAM privesc paths (CloudFox).", "HIGH", "7.5"),
    ("azure_managed_id_privesc", "Azure managed identity privesc.", "HIGH", "7.5"),
    ("gcp_sa_impersonation_privesc", "GCP SA impersonation privesc.", "HIGH", "7.5"),
]

router = make_advisory_router("privesc", TECHNIQUES,
    playbook_ref="See module_playbooks/12_privesc.md.")


def register(app):
    app.include_router(router)
