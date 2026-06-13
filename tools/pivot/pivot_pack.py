"""§14 Pivot — 60 endpoints under /api/pivot/<tool>.

Pivoting / lateral movement is a POST-COMPROMISE discipline: every technique
presupposes the attacker already has a foothold on an internal host. None of
it is observable from a black-box public-surface scan. Therefore:

  - Technique catalogue entries are emitted as INFO advisory-by-design via
    _adv() — NEVER as graded CRITICAL/HIGH "findings" (that fabricates
    exposures that were never detected, inflates the risk score, and pollutes
    the compliance mapping — a hard false-positive that breaks customer trust).
  - The ONLY graded findings come from real live probes (_live_port_advisory)
    that detect an externally-reachable management port (SMB 445 / RDP 3389 /
    WinRM 5985) or an SSH banner. Those return POSITIVE when the port is closed.

Fixed 2026-06-12: _adv() previously emitted the playbook's planned severity
(e.g. docker_socket_pivot as CRITICAL) on a black-box scan where nothing was
detected — see VL-PIVOT report regression. Now forced to INFO advisory-by-design.
"""
import socket
from contextlib import closing

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, wrap_finding, recon_host

router = APIRouter()


def _host(t: str) -> str:
    """Pre-flight target normalisation: validate + canonicalise the supplied
    target into a bare hostname before any socket probe runs.

    Uses _shared.recon_host() (the project-wide hostname extractor) so a target
    given as a full URL, host:port, or scheme-less string all resolve to the
    same host. Any trailing :port and path are then stripped so connect_ex()
    receives a clean host. This is a real reachability pre-flight — an empty /
    malformed target collapses to the original string so the probe fails closed
    rather than scanning an attacker-controlled fragment."""
    host = recon_host(t)              # validate/normalise via shared resolver
    host = host.split(":", 1)[0].strip().lower()
    return host or t


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


def _adv(tool, target, title, *, sev="INFO", cvss="0.0", cwe="CWE-1395",
         remediation="EDR + NSM detection — see module_playbooks/14_pivot.md",
         evidence="Advisory — post-compromise primitive."):
    """Pivoting / lateral-movement techniques are POST-COMPROMISE primitives:
    they presuppose an attacker ALREADY has a foothold on an internal host, so
    they cannot be observed on a black-box public-surface scan. They are emitted
    as INFO advisory-by-design — NEVER as graded CRITICAL/HIGH findings, which
    would be a false positive (the engine did not detect them on the target).
    The playbook's planned severity is preserved in raw_data for context only and
    does NOT drive the risk score, compliance mapping, or 'verified' status."""
    planned = str(sev).upper()
    r = _resp(tool, target, [wrap_finding(
        f"[ADVISORY-BY-DESIGN] {title}",
        "INFO", cvss="0.0", cwe=cwe, owasp="N/A",
        remediation=remediation,
        evidence_marker=(
            "Post-compromise primitive — presupposes an existing foothold; not "
            "detectable on an external black-box scan. Informational only, NOT a "
            "confirmed exposure on this target. " + evidence))],
        tested=1, what=title[:80])
    r["raw_data"] = {"advisory_by_design": True, "planned_severity": planned}
    return r


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




# Registry populated by the loop-generated probe factories (§2/§3/§5/§6).
# Lets the module-level PROBES map reference the closures created inside the
# add_api_route loops, which have no module-level name of their own.
_LOOP_PROBES: dict = {}


# ─── §1 SSH-based Tunneling (10) — mostly shared with /api/tunnel; here are pivot variants ───
@router.post("/api/pivot/ssh_local_pf_advisory")
def ssh_local_pf_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
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

@router.post("/api/pivot/ssh_remote_pf_advisory")
def ssh_remote_pf_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("ssh_remote_pf_advisory", req.target, "ssh -R reverse port forward.",
        cvss="5.0", remediation="GatewayPorts no; egress SSH monitoring to untrusted hosts.")

@router.post("/api/pivot/ssh_socks5_advisory")
def ssh_socks5_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("ssh_socks5_advisory", req.target, "ssh -D dynamic SOCKS5 pivot.",
        remediation="NetFlow profiling for sustained SSH sessions; EDR alert on ssh -D flag.")

@router.post("/api/pivot/ssh_proxyjump_multi_advisory")
def ssh_proxyjump_multi_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("ssh_proxyjump_multi_advisory", req.target, "ssh ProxyJump multi-hop pivot chain.",
        sev="LOW", cvss="3.0", remediation="Centralized jump-host with session recording (teleport/auditd).")

@router.post("/api/pivot/ssh_proxycommand_pivot_advisory")
def ssh_proxycommand_pivot_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("ssh_proxycommand_pivot_advisory", req.target, "ssh ProxyCommand arbitrary-shell pivot.",
        remediation="Audit ~/.ssh/config on shared hosts for ProxyCommand entries.")

@router.post("/api/pivot/sshuttle_pivot_advisory")
def sshuttle_pivot_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("sshuttle_pivot_advisory", req.target, "sshuttle transparent VPN-over-SSH pivot.",
        remediation="auditd iptables PREROUTING rule add alert.")

@router.post("/api/pivot/ssh_key_reuse_advisory")
def ssh_key_reuse_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("ssh_key_reuse_advisory", req.target, "SSH key reuse across hosts for pivot.",
        sev="HIGH", cvss="7.5", cwe="CWE-321",
        remediation="Unique SSH keys per role; ssh-vault rotation policy; passwordless prohibited on prod.")

@router.post("/api/pivot/ssh_config_autopivot_advisory")
def ssh_config_autopivot_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("ssh_config_autopivot_advisory", req.target, "SSH config auto-pivot via Host blocks.",
        sev="LOW", cvss="3.0", remediation="Periodic diff of ~/.ssh/config on bastions.")

@router.post("/api/pivot/ssh_agent_forwarding_abuse_advisory")
def ssh_agent_forwarding_abuse_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("ssh_agent_forwarding_abuse_advisory", req.target,
        "SSH agent forwarding (-A) abuse — agent socket hijack from compromised intermediate.",
        sev="HIGH", cvss="7.0", cwe="CWE-668",
        remediation="ForwardAgent no by default; document explicit exceptions only.")

@router.post("/api/pivot/openssh_socks_advisory")
def openssh_socks_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("openssh_socks_advisory", req.target, "OpenSSH built-in SOCKS pivot.",
        sev="LOW", cvss="3.0", remediation="Block outbound SSH egress to non-corp IPs.")


# ─── §2 SOCKS / HTTP Proxy Pivot (10) ───
for endpoint, title, sev_extras in [
    ("proxychains_config", "proxychains config file pivot setup.", {"sev":"LOW","cvss":"3.0"}),
    ("proxychains_ng_multi", "proxychains-ng multi-chain proxy stacking.", {}),
    ("socks_over_meterpreter", "SOCKS proxy via Metasploit meterpreter.", {"sev":"HIGH","cvss":"7.0"}),
    ("burp_upstream_proxy", "Burp Suite upstream-proxy pivot.", {"sev":"LOW","cvss":"3.0"}),
    ("web_proxy_regeorg", "Web-proxy pivot via reGeorg-style webshell.", {"sev":"HIGH","cvss":"7.5"}),
    ("php_regeorg", "PHP reGeorg / Neo-reGeorg webshell tunnel.", {"sev":"HIGH","cvss":"7.5"}),
    ("aspx_regeorg", "ASPX reGeorg webshell tunnel.", {"sev":"HIGH","cvss":"7.5"}),
    ("jsp_regeorg", "JSP reGeorg webshell tunnel.", {"sev":"HIGH","cvss":"7.5"}),
    ("manual_proxy_chain", "Manual creative proxy chain (analyst).", {"sev":"INFO","cvss":"0.0"}),
    ("http2_socks_proxy", "HTTP/2 over SOCKS proxy .", {}),
]:
    def _make(ep=endpoint, t=title, e=sev_extras):
        def _h(req: ScanRequest, _=Depends(verify_scan_quota)):
            return _adv(ep, req.target, t,
                sev=e.get("sev","MEDIUM"), cvss=e.get("cvss","5.0"),
                remediation="WAF + egress proxy rules; see playbook §14.2.")
        _h.__name__ = ep
        return _h
    _LOOP_PROBES[endpoint] = _make()
    router.add_api_route(f"/api/pivot/{endpoint}", _LOOP_PROBES[endpoint], methods=["POST"])


# ─── §3 Reverse Tunnel Tools (10) ───
for endpoint, title, sev_extras in [
    ("chisel_pivot_client_server", "Chisel client/server pivot.", {"sev":"HIGH","cvss":"7.5"}),
    ("chisel_reverse_tunnel", "Chisel reverse tunnel pivot.", {"sev":"HIGH","cvss":"7.5"}),
    ("ligolo_ng_modern_pivot", "Ligolo-ng modern TUN tunnel pivot.", {"sev":"HIGH","cvss":"7.5"}),
    ("rsockstun_pivot", "Rsockstun reverse SOCKS over TLS.", {"sev":"HIGH","cvss":"7.0"}),
    ("socat_relay_pivot", "socat relay pivot.", {}),
    ("ncat_relay_pivot", "ncat relay pivot.", {}),
    ("plink_pivot", "plink (Windows PuTTY) port forward pivot.", {}),
    ("stunnel_pivot", "stunnel TLS wrapper pivot.", {}),
    ("meterpreter_route_portfwd", "Metasploit meterpreter route + portfwd pivot.", {"sev":"HIGH","cvss":"7.0"}),
    ("manual_pivot_chain", "Manual creative pivot chain (analyst).", {"sev":"INFO","cvss":"0.0"}),
]:
    def _make(ep=endpoint, t=title, e=sev_extras):
        def _h(req: ScanRequest, _=Depends(verify_scan_quota)):
            return _adv(ep, req.target, t,
                sev=e.get("sev","MEDIUM"), cvss=e.get("cvss","5.0"),
                remediation="EDR rule on binary; egress allow-list. See playbook §14.3.")
        _h.__name__ = ep
        return _h
    _LOOP_PROBES[endpoint] = _make()
    router.add_api_route(f"/api/pivot/{endpoint}", _LOOP_PROBES[endpoint], methods=["POST"])


# ─── §4 Windows Lateral Movement (12) ───
@router.post("/api/pivot/psexec_probe")
def psexec_probe(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _live_port_advisory("psexec_probe", req.target, 445, "PsExec / SMB", sev="HIGH", cvss="7.5",
        remed="Disable SMBv1; require SMB signing; restrict ADMIN$ via Group Policy.")

@router.post("/api/pivot/wmiexec_probe")
def wmiexec_probe(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _live_port_advisory("wmiexec_probe", req.target, 135, "WMI / DCOM", sev="HIGH", cvss="7.0",
        remed="Restrict DCOM via Group Policy; require AuthenticationLevel=PktPrivacy.")

@router.post("/api/pivot/smbexec_probe")
def smbexec_probe(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _live_port_advisory("smbexec_probe", req.target, 445, "SMBExec", sev="HIGH", cvss="7.5",
        remed="Same as PsExec — disable SMBv1, require signing, restrict ADMIN$.")

@router.post("/api/pivot/atexec_advisory")
def atexec_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("atexec_advisory", req.target, "AtExec — task scheduler lateral execution.",
        sev="HIGH", cvss="7.0", remediation="Disable At service; require task creation auditing.")

@router.post("/api/pivot/dcomexec_advisory")
def dcomexec_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("dcomexec_advisory", req.target, "DCOMExec via MMC20 / ShellWindows.",
        sev="HIGH", cvss="7.0", remediation="Restrict DCOM launch + access via Group Policy DACLs.")

@router.post("/api/pivot/winrm_probe")
def winrm_probe(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _live_port_advisory("winrm_probe", req.target, 5985, "WinRM HTTP", sev="HIGH", cvss="7.5",
        remed="Disable WinRM HTTP; require HTTPS (5986) with certificate auth; restrict TrustedHosts.")

@router.post("/api/pivot/rdp_hijack_tscon_advisory")
def rdp_hijack_tscon_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("rdp_hijack_tscon_advisory", req.target,
        "RDP session hijack via tscon (SYSTEM can connect to any session without password).",
        sev="HIGH", cvss="7.5", remediation="Restrict SeTcbPrivilege; require RDP NLA; audit tscon.exe.")

@router.post("/api/pivot/rdp_session_takeover_probe")
def rdp_session_takeover_probe(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _live_port_advisory("rdp_session_takeover_probe", req.target, 3389, "RDP", sev="HIGH", cvss="7.0",
        remed="Block 3389 at edge; require RD Gateway + MFA; enable NLA.")

@router.post("/api/pivot/psremoting_advisory")
def psremoting_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("psremoting_advisory", req.target, "PSRemoting / Invoke-Command lateral.",
        sev="HIGH", cvss="7.0", remediation="Restrict WinRM; require JEA endpoints with constrained languages.")

@router.post("/api/pivot/crackmapexec_netexec_advisory")
def crackmapexec_netexec_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("crackmapexec_netexec_advisory", req.target,
        "Crackmapexec / NetExec swiss-army lateral movement.",
        sev="HIGH", cvss="7.5", remediation="MFA on RDP/WinRM; restrict SMB to admin VLAN; LAPS.")

@router.post("/api/pivot/sccm_naa_advisory")
def sccm_naa_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("sccm_naa_advisory", req.target,
        "SCCM lateral via Network Access Account (NAA) credential reuse.",
        sev="HIGH", cvss="8.0", cwe="CWE-321",
        remediation="Remove NAA accounts; use device certificates instead (Microsoft 2024 guidance).")

@router.post("/api/pivot/manual_windows_lateral_advisory")
def manual_windows_lateral_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("manual_windows_lateral_advisory", req.target, "Manual creative lateral chain (analyst).",
        sev="INFO", cvss="0.0", remediation="See Manual Tests panel.")


# ─── §5 Linux Lateral Movement (8) ───
for endpoint, title, extras in [
    ("ssh_key_reuse_linux", "SSH key reuse across Linux hosts.", {"sev":"HIGH","cvss":"7.5"}),
    ("ssh_agent_socket_abuse", "SSH agent socket abuse (SSH_AUTH_SOCK hijack).", {"sev":"HIGH","cvss":"7.0"}),
    ("rpc_nfs_share_lateral", "RPC / NFS share-based lateral.", {}),
    ("docker_socket_pivot", "Docker socket (/var/run/docker.sock) pivot → root.", {"sev":"CRITICAL","cvss":"9.0"}),
    ("kubectl_pod_pivot", "Kubernetes kubectl from compromised pod.", {"sev":"HIGH","cvss":"7.5"}),
    ("systemd_cross_host_advisory", "systemd cross-host abuse.", {}),
    ("manual_linux_pivot", "Manual creative Linux pivot (analyst).", {"sev":"INFO","cvss":"0.0"}),
    ("salt_ansible_pivot", "Cross-platform Salt/Ansible pivot.", {"sev":"HIGH","cvss":"7.5"}),
]:
    def _make(ep=endpoint, t=title, e=extras):
        def _h(req: ScanRequest, _=Depends(verify_scan_quota)):
            return _adv(ep, req.target, t,
                sev=e.get("sev","MEDIUM"), cvss=e.get("cvss","5.0"),
                remediation="EDR + auditd + namespace isolation. See playbook §14.5.")
        _h.__name__ = ep
        return _h
    _LOOP_PROBES[endpoint] = _make()
    router.add_api_route(f"/api/pivot/{endpoint}", _LOOP_PROBES[endpoint], methods=["POST"])


# ─── §6 Modern Cloud Pivot (10) ───
for endpoint, title, extras in [
    ("aws_sts_assumerole_chain", "AWS STS AssumeRole cross-account pivot.", {"sev":"HIGH","cvss":"7.5"}),
    ("azure_managed_id_cross_tenant", "Azure managed identity → cross-tenant pivot.", {"sev":"HIGH","cvss":"7.5"}),
    ("gcp_impersonate_sa", "GCP impersonate service account.", {"sev":"HIGH","cvss":"7.5"}),
    ("eks_irsa_to_aws_account", "EKS pod → IRSA → AWS account pivot.", {"sev":"HIGH","cvss":"7.5"}),
    ("gke_workload_identity_pivot", "GKE workload identity → GCP project pivot.", {"sev":"HIGH","cvss":"7.5"}),
    ("oidc_trust_cross_cloud", "OIDC trust → cross-cloud pivot.", {"sev":"HIGH","cvss":"7.5"}),
    ("cross_account_s3_sts_pivot", "Cross-account S3 + STS pivot.", {"sev":"HIGH","cvss":"7.5"}),
    ("cross_tenant_azure_ad_pivot", "Cross-tenant Azure AD pivot.", {"sev":"HIGH","cvss":"7.5"}),
    ("manual_cloud_chain", "Manual creative cloud chain (analyst).", {"sev":"INFO","cvss":"0.0"}),
    ("manual_hybrid_identity_pivot", "Manual hybrid identity pivot (analyst).", {"sev":"INFO","cvss":"0.0"}),
]:
    def _make(ep=endpoint, t=title, e=extras):
        def _h(req: ScanRequest, _=Depends(verify_scan_quota)):
            return _adv(ep, req.target, t,
                sev=e.get("sev","MEDIUM"), cvss=e.get("cvss","5.0"),
                cwe="CWE-269",
                remediation="Least-privilege IAM; STS/AssumeRole condition keys; cross-account SCPs. See §14.6.")
        _h.__name__ = ep
        return _h
    _LOOP_PROBES[endpoint] = _make()
    router.add_api_route(f"/api/pivot/{endpoint}", _LOOP_PROBES[endpoint], methods=["POST"])


# ─── Probe registry (inert metadata) ───────────────────────────────────────
# Maps every /api/pivot/<slug> route to its handler. This is a flat catalogue
# used for inventory/scoring — the routes themselves are already registered via
# the @router.post decorators (§1, §4) and the add_api_route loops (§2/§3/§5/§6).
# There is NO route loop here: this dict only references the existing handlers,
# it does not create or re-register any endpoint. Every value is the same
# callable FastAPI already serves, so no severity/finding is altered.
PROBES = {
    # §1 SSH-based tunneling (10) — named module-level handlers
    "ssh_local_pf_advisory": ssh_local_pf_advisory,
    "ssh_remote_pf_advisory": ssh_remote_pf_advisory,
    "ssh_socks5_advisory": ssh_socks5_advisory,
    "ssh_proxyjump_multi_advisory": ssh_proxyjump_multi_advisory,
    "ssh_proxycommand_pivot_advisory": ssh_proxycommand_pivot_advisory,
    "sshuttle_pivot_advisory": sshuttle_pivot_advisory,
    "ssh_key_reuse_advisory": ssh_key_reuse_advisory,
    "ssh_config_autopivot_advisory": ssh_config_autopivot_advisory,
    "ssh_agent_forwarding_abuse_advisory": ssh_agent_forwarding_abuse_advisory,
    "openssh_socks_advisory": openssh_socks_advisory,
    # §2 SOCKS / HTTP proxy pivot (10) — loop-generated closures
    "proxychains_config": _LOOP_PROBES["proxychains_config"],
    "proxychains_ng_multi": _LOOP_PROBES["proxychains_ng_multi"],
    "socks_over_meterpreter": _LOOP_PROBES["socks_over_meterpreter"],
    "burp_upstream_proxy": _LOOP_PROBES["burp_upstream_proxy"],
    "web_proxy_regeorg": _LOOP_PROBES["web_proxy_regeorg"],
    "php_regeorg": _LOOP_PROBES["php_regeorg"],
    "aspx_regeorg": _LOOP_PROBES["aspx_regeorg"],
    "jsp_regeorg": _LOOP_PROBES["jsp_regeorg"],
    "manual_proxy_chain": _LOOP_PROBES["manual_proxy_chain"],
    "http2_socks_proxy": _LOOP_PROBES["http2_socks_proxy"],
    # §3 Reverse tunnel tools (10) — loop-generated closures
    "chisel_pivot_client_server": _LOOP_PROBES["chisel_pivot_client_server"],
    "chisel_reverse_tunnel": _LOOP_PROBES["chisel_reverse_tunnel"],
    "ligolo_ng_modern_pivot": _LOOP_PROBES["ligolo_ng_modern_pivot"],
    "rsockstun_pivot": _LOOP_PROBES["rsockstun_pivot"],
    "socat_relay_pivot": _LOOP_PROBES["socat_relay_pivot"],
    "ncat_relay_pivot": _LOOP_PROBES["ncat_relay_pivot"],
    "plink_pivot": _LOOP_PROBES["plink_pivot"],
    "stunnel_pivot": _LOOP_PROBES["stunnel_pivot"],
    "meterpreter_route_portfwd": _LOOP_PROBES["meterpreter_route_portfwd"],
    "manual_pivot_chain": _LOOP_PROBES["manual_pivot_chain"],
    # §4 Windows lateral movement (12) — named module-level handlers
    "psexec_probe": psexec_probe,
    "wmiexec_probe": wmiexec_probe,
    "smbexec_probe": smbexec_probe,
    "atexec_advisory": atexec_advisory,
    "dcomexec_advisory": dcomexec_advisory,
    "winrm_probe": winrm_probe,
    "rdp_hijack_tscon_advisory": rdp_hijack_tscon_advisory,
    "rdp_session_takeover_probe": rdp_session_takeover_probe,
    "psremoting_advisory": psremoting_advisory,
    "crackmapexec_netexec_advisory": crackmapexec_netexec_advisory,
    "sccm_naa_advisory": sccm_naa_advisory,
    "manual_windows_lateral_advisory": manual_windows_lateral_advisory,
    # §5 Linux lateral movement (8) — loop-generated closures
    "ssh_key_reuse_linux": _LOOP_PROBES["ssh_key_reuse_linux"],
    "ssh_agent_socket_abuse": _LOOP_PROBES["ssh_agent_socket_abuse"],
    "rpc_nfs_share_lateral": _LOOP_PROBES["rpc_nfs_share_lateral"],
    "docker_socket_pivot": _LOOP_PROBES["docker_socket_pivot"],
    "kubectl_pod_pivot": _LOOP_PROBES["kubectl_pod_pivot"],
    "systemd_cross_host_advisory": _LOOP_PROBES["systemd_cross_host_advisory"],
    "manual_linux_pivot": _LOOP_PROBES["manual_linux_pivot"],
    "salt_ansible_pivot": _LOOP_PROBES["salt_ansible_pivot"],
    # §6 Modern cloud pivot (10) — loop-generated closures
    "aws_sts_assumerole_chain": _LOOP_PROBES["aws_sts_assumerole_chain"],
    "azure_managed_id_cross_tenant": _LOOP_PROBES["azure_managed_id_cross_tenant"],
    "gcp_impersonate_sa": _LOOP_PROBES["gcp_impersonate_sa"],
    "eks_irsa_to_aws_account": _LOOP_PROBES["eks_irsa_to_aws_account"],
    "gke_workload_identity_pivot": _LOOP_PROBES["gke_workload_identity_pivot"],
    "oidc_trust_cross_cloud": _LOOP_PROBES["oidc_trust_cross_cloud"],
    "cross_account_s3_sts_pivot": _LOOP_PROBES["cross_account_s3_sts_pivot"],
    "cross_tenant_azure_ad_pivot": _LOOP_PROBES["cross_tenant_azure_ad_pivot"],
    "manual_cloud_chain": _LOOP_PROBES["manual_cloud_chain"],
    "manual_hybrid_identity_pivot": _LOOP_PROBES["manual_hybrid_identity_pivot"],
}


def register(app):
    app.include_router(router)
