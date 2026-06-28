"""§14 Pivot — 60 endpoints under /api/pivot/<tool>.

Mostly post-compromise primitives — rendered as structured advisories
with detection guidance + remediation. Live probes where externally
observable (SSH banner / SMB / RDP port / kubernetes API).

Architecture: every endpoint is declared in the literal ``PROBES`` dict
(slug -> handler) and registered from it, matching the canonical pack-style
modules (exploit/bof/etc.). The orchestrator's PIVOT_TOOLS_BY_TIER mirrors
these slugs and fans them out through /api/pivot/run_all.
"""
import socket
from contextlib import closing

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, wrap_finding

router = APIRouter()


def _host(t: str) -> str:
    return t.split("://", 1)[-1].split("/")[0].split(":")[0].strip().lower() or t


def _resp(tool, target, findings, tested=1, what=""):
    sev_order = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"INFO":0,"POSITIVE":0}
    top = "INFO"
    for f in findings:
        s = str(f.get("severity","INFO")).upper()
        if sev_order.get(s,0) > sev_order.get(top,0): top = s
    return {"tool":tool,"target":target,"scan_time":0,
            "vulnerable": any(str(f.get("severity","")).upper() in ("CRITICAL","HIGH","MEDIUM") for f in findings),
            "severity": top, "findings": findings,
            "tests_performed": tested, "tests_summary": what or f"{tool}: {tested} check(s)",
            "raw_data": {}}


def _adv(tool, target, title, *, sev="MEDIUM", cvss="5.0", cwe="CWE-1395",
         remediation="EDR + NSM detection — see module_playbooks/14_pivot.md",
         evidence="Advisory — post-compromise primitive."):
    return _resp(tool, target, [wrap_finding(title, sev, cvss=cvss, cwe=cwe,
        owasp="A05:2021", remediation=remediation, evidence_marker=evidence)],
        tested=1, what=title[:80])


def _tcp_open(host, port, timeout=2.5):
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def _tcp_banner(host, port, timeout=2.5):
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) != 0: return ""
            try: return s.recv(256).decode("utf-8", errors="ignore").strip()
            except Exception: return ""
    except Exception:
        return ""


def _live_port_advisory(tool, target, port, name, sev="MEDIUM", cvss="5.0", remed=""):
    host = _host(target)
    open_ = _tcp_open(host, port)
    if open_:
        return _resp(tool, target, [wrap_finding(
            f"{name} port {port}/tcp reachable — lateral primitive available externally.",
            sev, cvss=cvss, cwe="CWE-1395", owasp="A05:2021",
            remediation=remed or f"Restrict {port}/tcp to admin VLAN.",
            evidence_marker=f"TCP/{port} open")], tested=1, what=f"{name} reachability")
    return _resp(tool, target, [wrap_finding(
        f"{name} port {port}/tcp NOT reachable externally.",
        "POSITIVE", cvss="0.0", cwe="N/A",
        remediation="Continue restricting management protocols.",
        evidence_marker=f"TCP/{port} closed")], tested=1, what=f"{name} reachability")


# ─── Handler factories ───────────────────────────────────────────────
# Each returns a FastAPI endpoint handler with the standard
# (req, verify_scan_quota) signature, capturing its per-endpoint params.

def _adv_h(slug, title, *, sev="MEDIUM", cvss="5.0", cwe="CWE-1395", remediation=""):
    """Static advisory endpoint — structured post-compromise primitive."""
    def _h(req: ScanRequest, _=Depends(verify_scan_quota)):
        return _adv(slug, req.target, title, sev=sev, cvss=cvss, cwe=cwe,
                    remediation=remediation)
    _h.__name__ = slug
    return _h


def _port_h(slug, port, name, *, sev="MEDIUM", cvss="5.0", remed=""):
    """Live endpoint — TCP reachability of a lateral-movement service port."""
    def _h(req: ScanRequest, _=Depends(verify_scan_quota)):
        return _live_port_advisory(slug, req.target, port, name,
                                   sev=sev, cvss=cvss, remed=remed)
    _h.__name__ = slug
    return _h


def _ssh_local_pf(req: ScanRequest, _=Depends(verify_scan_quota)):
    """Live SSH banner grab on 22/tcp — local-port-forward primitive."""
    host = _host(req.target); banner = _tcp_banner(host, 22)
    if banner.startswith("SSH-"):
        return _resp("ssh_local_pf_advisory", req.target, [wrap_finding(
            f"SSH-L pivot primitive available — banner: {banner[:80]}",
            "INFO", cvss="0.0", cwe="CWE-1395",
            remediation="AllowTcpForwarding no for restricted users; jump-host architecture.",
            evidence_marker=f"SSH banner on 22/tcp: {banner[:100]}")], tested=1,
            what="SSH local-port-forward primitive")
    return _adv("ssh_local_pf_advisory", req.target, "SSH not exposed on 22/tcp — primitive not reachable.",
        sev="INFO", cvss="0.0", cwe="N/A", remediation="Audit non-standard SSH ports.")


# ─── PROBES: every /api/pivot/<slug> endpoint (60) ───────────────────
PROBES = {
    # §1 SSH-based Tunneling (10) — live banner + ssh-config primitives
    "ssh_local_pf_advisory": _ssh_local_pf,
    "ssh_remote_pf_advisory": _adv_h("ssh_remote_pf_advisory", "ssh -R reverse port forward.",
        cvss="5.0", remediation="GatewayPorts no; egress SSH monitoring to untrusted hosts."),
    "ssh_socks5_advisory": _adv_h("ssh_socks5_advisory", "ssh -D dynamic SOCKS5 pivot.",
        remediation="NetFlow profiling for sustained SSH sessions; EDR alert on ssh -D flag."),
    "ssh_proxyjump_multi_advisory": _adv_h("ssh_proxyjump_multi_advisory", "ssh ProxyJump multi-hop pivot chain.",
        sev="LOW", cvss="3.0", remediation="Centralized jump-host with session recording (teleport/auditd)."),
    "ssh_proxycommand_pivot_advisory": _adv_h("ssh_proxycommand_pivot_advisory", "ssh ProxyCommand arbitrary-shell pivot.",
        remediation="Audit ~/.ssh/config on shared hosts for ProxyCommand entries."),
    "sshuttle_pivot_advisory": _adv_h("sshuttle_pivot_advisory", "sshuttle transparent VPN-over-SSH pivot.",
        remediation="auditd iptables PREROUTING rule add alert."),
    "ssh_key_reuse_advisory": _adv_h("ssh_key_reuse_advisory", "SSH key reuse across hosts for pivot.",
        sev="HIGH", cvss="7.5", cwe="CWE-321",
        remediation="Unique SSH keys per role; ssh-vault rotation policy; passwordless prohibited on prod."),
    "ssh_config_autopivot_advisory": _adv_h("ssh_config_autopivot_advisory", "SSH config auto-pivot via Host blocks.",
        sev="LOW", cvss="3.0", remediation="Periodic diff of ~/.ssh/config on bastions."),
    "ssh_agent_forwarding_abuse_advisory": _adv_h("ssh_agent_forwarding_abuse_advisory",
        "SSH agent forwarding (-A) abuse — agent socket hijack from compromised intermediate.",
        sev="HIGH", cvss="7.0", cwe="CWE-668",
        remediation="ForwardAgent no by default; document explicit exceptions only."),
    "openssh_socks_advisory": _adv_h("openssh_socks_advisory", "OpenSSH built-in SOCKS pivot.",
        sev="LOW", cvss="3.0", remediation="Block outbound SSH egress to non-corp IPs."),

    # §2 SOCKS / HTTP Proxy Pivot (10)
    "proxychains_config": _adv_h("proxychains_config", "proxychains config file pivot setup.",
        sev="LOW", cvss="3.0", remediation="WAF + egress proxy rules; see playbook §14.2."),
    "proxychains_ng_multi": _adv_h("proxychains_ng_multi", "proxychains-ng multi-chain proxy stacking.",
        remediation="WAF + egress proxy rules; see playbook §14.2."),
    "socks_over_meterpreter": _adv_h("socks_over_meterpreter", "SOCKS proxy via Metasploit meterpreter.",
        sev="HIGH", cvss="7.0", remediation="WAF + egress proxy rules; see playbook §14.2."),
    "burp_upstream_proxy": _adv_h("burp_upstream_proxy", "Burp Suite upstream-proxy pivot.",
        sev="LOW", cvss="3.0", remediation="WAF + egress proxy rules; see playbook §14.2."),
    "web_proxy_regeorg": _adv_h("web_proxy_regeorg", "Web-proxy pivot via reGeorg-style webshell.",
        sev="HIGH", cvss="7.5", remediation="WAF + egress proxy rules; see playbook §14.2."),
    "php_regeorg": _adv_h("php_regeorg", "PHP reGeorg / Neo-reGeorg webshell tunnel.",
        sev="HIGH", cvss="7.5", remediation="WAF + egress proxy rules; see playbook §14.2."),
    "aspx_regeorg": _adv_h("aspx_regeorg", "ASPX reGeorg webshell tunnel.",
        sev="HIGH", cvss="7.5", remediation="WAF + egress proxy rules; see playbook §14.2."),
    "jsp_regeorg": _adv_h("jsp_regeorg", "JSP reGeorg webshell tunnel.",
        sev="HIGH", cvss="7.5", remediation="WAF + egress proxy rules; see playbook §14.2."),
    "manual_proxy_chain": _adv_h("manual_proxy_chain", "Manual creative proxy chain (analyst).",
        sev="INFO", cvss="0.0", remediation="WAF + egress proxy rules; see playbook §14.2."),
    "http2_socks_proxy": _adv_h("http2_socks_proxy", "HTTP/2 over SOCKS proxy .",
        remediation="WAF + egress proxy rules; see playbook §14.2."),

    # §3 Reverse Tunnel Tools (10)
    "chisel_pivot_client_server": _adv_h("chisel_pivot_client_server", "Chisel client/server pivot.",
        sev="HIGH", cvss="7.5", remediation="EDR rule on binary; egress allow-list. See playbook §14.3."),
    "chisel_reverse_tunnel": _adv_h("chisel_reverse_tunnel", "Chisel reverse tunnel pivot.",
        sev="HIGH", cvss="7.5", remediation="EDR rule on binary; egress allow-list. See playbook §14.3."),
    "ligolo_ng_modern_pivot": _adv_h("ligolo_ng_modern_pivot", "Ligolo-ng modern TUN tunnel pivot.",
        sev="HIGH", cvss="7.5", remediation="EDR rule on binary; egress allow-list. See playbook §14.3."),
    "rsockstun_pivot": _adv_h("rsockstun_pivot", "Rsockstun reverse SOCKS over TLS.",
        sev="HIGH", cvss="7.0", remediation="EDR rule on binary; egress allow-list. See playbook §14.3."),
    "socat_relay_pivot": _adv_h("socat_relay_pivot", "socat relay pivot.",
        remediation="EDR rule on binary; egress allow-list. See playbook §14.3."),
    "ncat_relay_pivot": _adv_h("ncat_relay_pivot", "ncat relay pivot.",
        remediation="EDR rule on binary; egress allow-list. See playbook §14.3."),
    "plink_pivot": _adv_h("plink_pivot", "plink (Windows PuTTY) port forward pivot.",
        remediation="EDR rule on binary; egress allow-list. See playbook §14.3."),
    "stunnel_pivot": _adv_h("stunnel_pivot", "stunnel TLS wrapper pivot.",
        remediation="EDR rule on binary; egress allow-list. See playbook §14.3."),
    "meterpreter_route_portfwd": _adv_h("meterpreter_route_portfwd", "Metasploit meterpreter route + portfwd pivot.",
        sev="HIGH", cvss="7.0", remediation="EDR rule on binary; egress allow-list. See playbook §14.3."),
    "manual_pivot_chain": _adv_h("manual_pivot_chain", "Manual creative pivot chain (analyst).",
        sev="INFO", cvss="0.0", remediation="EDR rule on binary; egress allow-list. See playbook §14.3."),

    # §4 Windows Lateral Movement (12) — live port probes + advisories
    "psexec_probe": _port_h("psexec_probe", 445, "PsExec / SMB", sev="HIGH", cvss="7.5",
        remed="Disable SMBv1; require SMB signing; restrict ADMIN$ via Group Policy."),
    "wmiexec_probe": _port_h("wmiexec_probe", 135, "WMI / DCOM", sev="HIGH", cvss="7.0",
        remed="Restrict DCOM via Group Policy; require AuthenticationLevel=PktPrivacy."),
    "smbexec_probe": _port_h("smbexec_probe", 445, "SMBExec", sev="HIGH", cvss="7.5",
        remed="Same as PsExec — disable SMBv1, require signing, restrict ADMIN$."),
    "atexec_advisory": _adv_h("atexec_advisory", "AtExec — task scheduler lateral execution.",
        sev="HIGH", cvss="7.0", remediation="Disable At service; require task creation auditing."),
    "dcomexec_advisory": _adv_h("dcomexec_advisory", "DCOMExec via MMC20 / ShellWindows.",
        sev="HIGH", cvss="7.0", remediation="Restrict DCOM launch + access via Group Policy DACLs."),
    "winrm_probe": _port_h("winrm_probe", 5985, "WinRM HTTP", sev="HIGH", cvss="7.5",
        remed="Disable WinRM HTTP; require HTTPS (5986) with certificate auth; restrict TrustedHosts."),
    "rdp_hijack_tscon_advisory": _adv_h("rdp_hijack_tscon_advisory",
        "RDP session hijack via tscon (SYSTEM can connect to any session without password).",
        sev="HIGH", cvss="7.5", remediation="Restrict SeTcbPrivilege; require RDP NLA; audit tscon.exe."),
    "rdp_session_takeover_probe": _port_h("rdp_session_takeover_probe", 3389, "RDP", sev="HIGH", cvss="7.0",
        remed="Block 3389 at edge; require RD Gateway + MFA; enable NLA."),
    "psremoting_advisory": _adv_h("psremoting_advisory", "PSRemoting / Invoke-Command lateral.",
        sev="HIGH", cvss="7.0", remediation="Restrict WinRM; require JEA endpoints with constrained languages."),
    "crackmapexec_netexec_advisory": _adv_h("crackmapexec_netexec_advisory",
        "Crackmapexec / NetExec swiss-army lateral movement.",
        sev="HIGH", cvss="7.5", remediation="MFA on RDP/WinRM; restrict SMB to admin VLAN; LAPS."),
    "sccm_naa_advisory": _adv_h("sccm_naa_advisory",
        "SCCM lateral via Network Access Account (NAA) credential reuse.",
        sev="HIGH", cvss="8.0", cwe="CWE-321",
        remediation="Remove NAA accounts; use device certificates instead (Microsoft 2024 guidance)."),
    "manual_windows_lateral_advisory": _adv_h("manual_windows_lateral_advisory",
        "Manual creative lateral chain (analyst).",
        sev="INFO", cvss="0.0", remediation="See Manual Tests panel."),

    # §5 Linux Lateral Movement (8)
    "ssh_key_reuse_linux": _adv_h("ssh_key_reuse_linux", "SSH key reuse across Linux hosts.",
        sev="HIGH", cvss="7.5", remediation="EDR + auditd + namespace isolation. See playbook §14.5."),
    "ssh_agent_socket_abuse": _adv_h("ssh_agent_socket_abuse", "SSH agent socket abuse (SSH_AUTH_SOCK hijack).",
        sev="HIGH", cvss="7.0", remediation="EDR + auditd + namespace isolation. See playbook §14.5."),
    "rpc_nfs_share_lateral": _adv_h("rpc_nfs_share_lateral", "RPC / NFS share-based lateral.",
        remediation="EDR + auditd + namespace isolation. See playbook §14.5."),
    "docker_socket_pivot": _adv_h("docker_socket_pivot", "Docker socket (/var/run/docker.sock) pivot → root.",
        sev="CRITICAL", cvss="9.0", remediation="EDR + auditd + namespace isolation. See playbook §14.5."),
    "kubectl_pod_pivot": _adv_h("kubectl_pod_pivot", "Kubernetes kubectl from compromised pod.",
        sev="HIGH", cvss="7.5", remediation="EDR + auditd + namespace isolation. See playbook §14.5."),
    "systemd_cross_host_advisory": _adv_h("systemd_cross_host_advisory", "systemd cross-host abuse.",
        remediation="EDR + auditd + namespace isolation. See playbook §14.5."),
    "manual_linux_pivot": _adv_h("manual_linux_pivot", "Manual creative Linux pivot (analyst).",
        sev="INFO", cvss="0.0", remediation="EDR + auditd + namespace isolation. See playbook §14.5."),
    "salt_ansible_pivot": _adv_h("salt_ansible_pivot", "Cross-platform Salt/Ansible pivot.",
        sev="HIGH", cvss="7.5", remediation="EDR + auditd + namespace isolation. See playbook §14.5."),

    # §6 Modern Cloud Pivot (10)
    "aws_sts_assumerole_chain": _adv_h("aws_sts_assumerole_chain", "AWS STS AssumeRole cross-account pivot.",
        sev="HIGH", cvss="7.5", cwe="CWE-269",
        remediation="Least-privilege IAM; STS/AssumeRole condition keys; cross-account SCPs. See §14.6."),
    "azure_managed_id_cross_tenant": _adv_h("azure_managed_id_cross_tenant", "Azure managed identity → cross-tenant pivot.",
        sev="HIGH", cvss="7.5", cwe="CWE-269",
        remediation="Least-privilege IAM; STS/AssumeRole condition keys; cross-account SCPs. See §14.6."),
    "gcp_impersonate_sa": _adv_h("gcp_impersonate_sa", "GCP impersonate service account.",
        sev="HIGH", cvss="7.5", cwe="CWE-269",
        remediation="Least-privilege IAM; STS/AssumeRole condition keys; cross-account SCPs. See §14.6."),
    "eks_irsa_to_aws_account": _adv_h("eks_irsa_to_aws_account", "EKS pod → IRSA → AWS account pivot.",
        sev="HIGH", cvss="7.5", cwe="CWE-269",
        remediation="Least-privilege IAM; STS/AssumeRole condition keys; cross-account SCPs. See §14.6."),
    "gke_workload_identity_pivot": _adv_h("gke_workload_identity_pivot", "GKE workload identity → GCP project pivot.",
        sev="HIGH", cvss="7.5", cwe="CWE-269",
        remediation="Least-privilege IAM; STS/AssumeRole condition keys; cross-account SCPs. See §14.6."),
    "oidc_trust_cross_cloud": _adv_h("oidc_trust_cross_cloud", "OIDC trust → cross-cloud pivot.",
        sev="HIGH", cvss="7.5", cwe="CWE-269",
        remediation="Least-privilege IAM; STS/AssumeRole condition keys; cross-account SCPs. See §14.6."),
    "cross_account_s3_sts_pivot": _adv_h("cross_account_s3_sts_pivot", "Cross-account S3 + STS pivot.",
        sev="HIGH", cvss="7.5", cwe="CWE-269",
        remediation="Least-privilege IAM; STS/AssumeRole condition keys; cross-account SCPs. See §14.6."),
    "cross_tenant_azure_ad_pivot": _adv_h("cross_tenant_azure_ad_pivot", "Cross-tenant Azure AD pivot.",
        sev="HIGH", cvss="7.5", cwe="CWE-269",
        remediation="Least-privilege IAM; STS/AssumeRole condition keys; cross-account SCPs. See §14.6."),
    "manual_cloud_chain": _adv_h("manual_cloud_chain", "Manual creative cloud chain (analyst).",
        sev="INFO", cvss="0.0", cwe="CWE-269",
        remediation="Least-privilege IAM; STS/AssumeRole condition keys; cross-account SCPs. See §14.6."),
    "manual_hybrid_identity_pivot": _adv_h("manual_hybrid_identity_pivot", "Manual hybrid identity pivot (analyst).",
        sev="INFO", cvss="0.0", cwe="CWE-269",
        remediation="Least-privilege IAM; STS/AssumeRole condition keys; cross-account SCPs. See §14.6."),
}


for _slug, _handler in PROBES.items():
    router.add_api_route(f"/api/pivot/{_slug}", _handler, methods=["POST"])


def register(app):
    app.include_router(router)
