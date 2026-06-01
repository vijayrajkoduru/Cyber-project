"""§15 Tunneling — 48 endpoints (live probes + advisories).

Section layout:
  §1 SSH Tunnel Primitives           (10 endpoints — ssh banner / config posture)
  §2 Reverse Tunneling Tools         (12 endpoints — chisel/ligolo/frp fingerprints)
  §3 DNS / ICMP Tunneling            ( 8 endpoints — dnscat2/iodine / DoH)
  §4 HTTP / HTTPS Tunneling          ( 8 endpoints — CONNECT, reGeorg sigs)
  §5 Modern Tunneling (Wg / QUIC) (10 endpoints — WG/Tailscale/Ngrok/Cloudflared)
"""
import socket
from contextlib import closing

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, wrap_finding, safe_get, web_url

router = APIRouter()


# ─────────────── helpers ───────────────
def _host(target: str) -> str:
    s = target.split("://", 1)[-1].split("/")[0].split(":")[0]
    return s.strip().lower() or target


def _resp(tool: str, target: str, findings: list, tested: int = 1,
          what_checked: str = "", raw: dict | None = None) -> dict:
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    top = "INFO"
    for f in findings:
        s = str(f.get("severity", "INFO")).upper()
        if sev_order.get(s, 0) > sev_order.get(top, 0):
            top = s
    return {
        "tool": tool, "target": target, "scan_time": 0,
        "vulnerable": any(str(f.get("severity", "")).upper() in
                          ("CRITICAL", "HIGH", "MEDIUM") for f in findings),
        "severity": top,
        "findings": findings,
        "tests_performed": tested,
        "tests_summary": what_checked or f"{tool}: {tested} checks",
        "raw_data": raw or {},
    }


def _adv(tool: str, target: str, title: str, *, sev: str = "MEDIUM",
         cvss: str = "5.0", cwe: str = "CWE-1395", remediation: str = "",
         evidence: str = "") -> dict:
    return _resp(tool, target, findings=[wrap_finding(
        title, sev, cvss=cvss, cwe=cwe, owasp="A05:2021",
        remediation=remediation or "Detect via host EDR + NSM. See module_playbooks/15_tunnel.md.",
        evidence_marker=evidence or "Advisory — post-compromise primitive; verify against EDR/NSM logs."
    )], tested=1, what_checked=title[:80])


def _udp_listen(host: str, port: int, timeout: float = 2.0) -> bool:
    """Probe UDP open by sending empty datagram and waiting briefly for ICMP unreachable.

    UDP is connectionless; this is best-effort and treats no ICMP-error as "potentially open".
    Used for WireGuard (51820), Tailscale (41641), ZeroTier (9993).
    """
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
            s.settimeout(timeout)
            s.sendto(b"\x00" * 8, (host, port))
            try:
                s.recvfrom(1500)
                return True
            except socket.timeout:
                return True  # no ICMP-unreachable received → likely open or filtered
            except OSError:
                return False
    except Exception:
        return False


def _tcp_open(host: str, port: int, timeout: float = 2.5) -> bool:
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def _tcp_banner(host: str, port: int, timeout: float = 2.5) -> str:
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) != 0:
                return ""
            try:
                return s.recv(256).decode("utf-8", errors="ignore").strip()
            except Exception:
                return ""
    except Exception:
        return ""


# ═══════════════ §1 — SSH Tunnel Primitives (10) ═══════════════

@router.post("/api/tunnel/ssh_local_forward_advisory")
def ssh_local_forward_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = _host(req.target)
    banner = _tcp_banner(host, 22)
    findings = []
    if banner.startswith("SSH-"):
        findings.append(wrap_finding(
            f"SSH-L (local port forward) primitive available — server banner: {banner[:80]}",
            "INFO", cvss="0.0", cwe="CWE-1395",
            remediation="Disable AllowTcpForwarding in /etc/ssh/sshd_config for restricted users; "
                        "use AllowAgentForwarding no; Match Group + ForceCommand for jump-only accounts.",
            evidence_marker=f"Port 22 open; banner: {banner[:100]}"))
    else:
        findings.append(wrap_finding(
            "SSH not exposed on port 22 — `ssh -L` primitive not reachable from this perspective.",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Audit non-standard SSH ports via full nmap sweep.",
            evidence_marker="No SSH banner on 22/tcp"))
    return _resp("ssh_local_forward_advisory", req.target, findings,
                 raw={"banner": banner})


@router.post("/api/tunnel/ssh_remote_forward_advisory")
def ssh_remote_forward_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("ssh_remote_forward_advisory", req.target,
        "ssh -R reverse forward primitive — attacker exposes attacker-side port via target's SSH client.",
        sev="MEDIUM", cvss="5.0",
        remediation="Set GatewayPorts no (default) in sshd_config; monitor outbound SSH to non-corporate IPs.",
        evidence="Post-compromise primitive — detect via egress monitoring of SSH to untrusted hosts.")


@router.post("/api/tunnel/ssh_dynamic_socks5_advisory")
def ssh_dynamic_socks5_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("ssh_dynamic_socks5_advisory", req.target,
        "ssh -D dynamic SOCKS5 — attacker tunnels arbitrary TCP via SSH session.",
        sev="MEDIUM", cvss="5.0",
        remediation="Restrict outbound SSH at egress firewall; require SSH session recording (auditd/teleport).",
        evidence="Detect via unusual SSH bandwidth + connection duration in NetFlow.")


@router.post("/api/tunnel/ssh_proxyjump_advisory")
def ssh_proxyjump_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("ssh_proxyjump_advisory", req.target,
        "ssh -J ProxyJump multi-hop pivot.",
        sev="LOW", cvss="3.0",
        remediation="Enforce jump-host architecture intentionally; log all SSH connections at jump host.",
        evidence="Legitimate jump architecture if intentional; flag chained jumps in audit logs.")


@router.post("/api/tunnel/ssh_proxycommand_advisory")
def ssh_proxycommand_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("ssh_proxycommand_advisory", req.target,
        "ssh ProxyCommand — arbitrary shell command as SSH transport (corkscrew/socat).",
        sev="MEDIUM", cvss="5.0",
        remediation="Audit ~/.ssh/config for ProxyCommand entries on shared hosts.",
        evidence="Often combined with corkscrew for HTTP-CONNECT egress bypass.")


@router.post("/api/tunnel/sshuttle_advisory")
def sshuttle_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("sshuttle_advisory", req.target,
        "sshuttle — transparent VPN-over-SSH (no server-side install required).",
        sev="MEDIUM", cvss="5.5",
        remediation="Block iptables NAT changes by non-root; alert on Python+SSH outbound from user sessions.",
        evidence="sshuttle uses iptables PREROUTING — detect via auditd iptables rule add.")


@router.post("/api/tunnel/ssh_detached_advisory")
def ssh_detached_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("ssh_detached_advisory", req.target,
        "ssh -N -f — detached tunnel running as background daemon.",
        sev="LOW", cvss="3.0",
        remediation="Process auditing — flag ssh processes with -N -f flags in psaux.",
        evidence="Persistence pattern; falcon/EDR rule: ssh -N -f from user shell.")


@router.post("/api/tunnel/ssh_config_match_advisory")
def ssh_config_match_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("ssh_config_match_advisory", req.target,
        "SSH config Match host blocks — per-target ProxyCommand auto-pivot.",
        sev="LOW", cvss="3.0",
        remediation="Periodically diff ~/.ssh/config on bastions/build hosts for unauthorized Match blocks.",
        evidence="Stealthy persistence — config-as-code review.")


@router.post("/api/tunnel/ssh_agent_forward_advisory")
def ssh_agent_forward_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("ssh_agent_forward_advisory", req.target,
        "SSH agent forwarding (-A) — compromised intermediate can hijack agent socket.",
        sev="HIGH", cvss="7.0", cwe="CWE-668",
        remediation="ForwardAgent no by default; document explicit exceptions; use signed certificates with TTL.",
        evidence="Classic lateral movement primitive — see CVE-2023-38408 family.")


@router.post("/api/tunnel/openssh_socks_advisory")
def openssh_socks_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("openssh_socks_advisory", req.target,
        "OpenSSH built-in SOCKS — no extra client tool needed for pivot.",
        sev="LOW", cvss="3.0",
        remediation="Detect via outbound SSH bandwidth profile; block non-corporate SSH egress.",
        evidence="Default behavior on every OpenSSH client.")


# ═══════════════ §2 — Reverse Tunneling Tools (12) ═══════════════

@router.post("/api/tunnel/chisel_fingerprint")
def chisel_fingerprint(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target)
    findings, intel = [], {}
    # Chisel server responds with characteristic 404 + Server header on /. Default port 8080.
    for path in ["/", "/chisel"]:
        r = safe_get(base.rstrip("/") + path, req=req, timeout=4)
        if r and ("chisel" in (r.headers.get("server", "") or "").lower() or
                  "chisel" in (r.text or "").lower()):
            findings.append(wrap_finding(
                "Chisel reverse-tunnel server fingerprint detected.",
                "HIGH", cvss="7.5", cwe="CWE-693", owasp="A05:2021",
                remediation="Block outbound websocket to non-corp endpoints; alert on chisel binary.",
                evidence_marker=f"Server header / body matched 'chisel' on {path}"))
            intel["chisel_endpoint"] = path
            break
    if not findings:
        findings.append(wrap_finding(
            "No Chisel fingerprint on web root — host-level audit still recommended.",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Periodically audit running processes for `chisel` on internet-exposed hosts.",
            evidence_marker="Negative web probe"))
    return _resp("chisel_fingerprint", req.target, findings, tested=2,
                 what_checked="Chisel server fingerprint via HTTP probe", raw=intel)


@router.post("/api/tunnel/ligolo_ng_advisory")
def ligolo_ng_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("ligolo_ng_advisory", req.target,
        "Ligolo-ng TUN-based reverse tunnel — faster than chisel, harder to fingerprint.",
        sev="HIGH", cvss="7.0",
        remediation="EDR rule: `ligolo` binary hash; outbound TLS to unexpected ports; tun0 created by non-root.",
        evidence="Modern (2023+) post-exploit tool; flag rapid lateral movement after agent install.")


@router.post("/api/tunnel/rsockstun_advisory")
def rsockstun_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("rsockstun_advisory", req.target,
        "Rsockstun — reverse SOCKS over TLS with built-in retry.",
        sev="HIGH", cvss="7.0",
        remediation="Block outbound TLS to non-allowlisted SNIs; deploy TLS interception on egress proxy.")


@router.post("/api/tunnel/socat_advisory")
def socat_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("socat_advisory", req.target,
        "socat — Swiss-army-knife relay; arbitrary protocol bridging.",
        sev="MEDIUM", cvss="5.5",
        remediation="Process auditing: alert on `socat` invocations with TCP-LISTEN or OPENSSL targets.",
        evidence="Common in red-team toolkits; not legitimate on most prod systems.")


@router.post("/api/tunnel/ncat_listen_advisory")
def ncat_listen_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("ncat_listen_advisory", req.target,
        "ncat --listen — encrypted bind shell / relay.",
        sev="MEDIUM", cvss="5.5",
        remediation="auditd rule on /usr/bin/ncat exec; block bind shells via SELinux/AppArmor.")


@router.post("/api/tunnel/plink_advisory")
def plink_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("plink_advisory", req.target,
        "plink.exe (PuTTY) — Windows reverse SSH tunnel.",
        sev="MEDIUM", cvss="5.5",
        remediation="Application allow-listing (WDAC/AppLocker) — block PuTTY suite on workstations.",
        evidence="Common LOLBAS for Windows-side tunneling.")


@router.post("/api/tunnel/frp_fingerprint")
def frp_fingerprint(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target)
    findings, intel = [], {}
    # frp dashboard default port 7500 with HTTP basic auth banner.
    for path in ["/", "/api/status", "/static/index.html"]:
        r = safe_get(base.rstrip("/") + path, req=req, timeout=4)
        if r and ("frp" in (r.headers.get("server", "") or "").lower() or
                  "frp" in (r.text or "").lower()[:5000]):
            findings.append(wrap_finding(
                "frp (fast reverse proxy) fingerprint detected.",
                "HIGH", cvss="7.5", cwe="CWE-693", owasp="A05:2021",
                remediation="Audit binary; restrict outbound WS/TLS to allow-listed servers.",
                evidence_marker=f"frp signature on {path}"))
            intel["frp_endpoint"] = path
            break
    if not findings:
        findings.append(wrap_finding(
            "No frp fingerprint on web root.",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Audit running processes for `frpc`/`frps` on exposed hosts.",
            evidence_marker="Negative web probe"))
    return _resp("frp_fingerprint", req.target, findings, tested=3,
                 what_checked="frp fingerprint via HTTP probe", raw=intel)


@router.post("/api/tunnel/regeorg_advisory")
def regeorg_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("regeorg_advisory", req.target,
        "reGeorg (legacy) — webshell tunnel using only HTTP GET/POST.",
        sev="HIGH", cvss="7.5",
        remediation="WAF rule: block requests with `cmd=connect` query + base64 body to .php/.jsp/.aspx URIs.",
        evidence="Detect via 'tunnel.php' / 'tunnel.jsp' filenames + sustained POST traffic.")


@router.post("/api/tunnel/neo_regeorg_advisory")
def neo_regeorg_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("neo_regeorg_advisory", req.target,
        "Neo-reGeorg — modern reGeorg fork with encryption and more polyglots.",
        sev="HIGH", cvss="7.5",
        remediation="WAF rule: alert on POST with high-entropy body to webshell-pattern URIs.")


@router.post("/api/tunnel/pivotnacci_advisory")
def pivotnacci_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("pivotnacci_advisory", req.target,
        "Pivotnacci — SOCKS server through HTTP webshells (modern).",
        sev="HIGH", cvss="7.5",
        remediation="Inspect webshell file upload + entropy on body; alert on long-lived HTTP sessions.")


@router.post("/api/tunnel/stunnel_advisory")
def stunnel_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("stunnel_advisory", req.target,
        "stunnel TLS wrapper — wraps plaintext protocols in TLS.",
        sev="MEDIUM", cvss="5.0",
        remediation="JA3/JA4 fingerprint outbound TLS — flag self-signed certs + stunnel default OpenSSL signature.")


@router.post("/api/tunnel/manual_creative_tunnel_chain_advisory")
def manual_creative_tunnel_chain_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("manual_creative_tunnel_chain_advisory", req.target,
        "Manual creative tunnel chain — analyst-only.",
        sev="INFO", cvss="0.0", cwe="N/A",
        remediation="See Manual Tests panel for analyst-attested chain documentation.")


# ═══════════════ §3 — DNS / ICMP Tunneling (8) ═══════════════

@router.post("/api/tunnel/dnscat2_advisory")
def dnscat2_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("dnscat2_advisory", req.target,
        "dnscat2 — DNS-tunnel C2; encrypted, authenticated.",
        sev="HIGH", cvss="7.0",
        remediation="DNS query length anomaly detection (>40 char subdomains); flag high-entropy DNS subdomains.",
        evidence="Splunk/Zeek rule: subdomain length > 40 + entropy > 4.0 → dnscat2 signature.")


@router.post("/api/tunnel/iodine_advisory")
def iodine_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("iodine_advisory", req.target,
        "iodine — IP-over-DNS; high-throughput DNS tunnel.",
        sev="HIGH", cvss="7.0",
        remediation="Same DNS anomaly detection as dnscat2. Block outbound DNS to non-corp resolvers.")


@router.post("/api/tunnel/dnstunnel_advisory")
def dnstunnel_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("dnstunnel_advisory", req.target,
        "DNStunnel (legacy) — TXT/NULL record exfil.",
        sev="MEDIUM", cvss="6.0",
        remediation="Alert on TXT-record query bursts; rate-limit TXT queries per source.")


@router.post("/api/tunnel/doh_tunnel_fingerprint")
def doh_tunnel_fingerprint(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target)
    findings, intel = [], {}
    # DNS-over-HTTPS endpoints respond to /dns-query with content-type application/dns-message
    for path in ["/dns-query", "/resolve"]:
        r = safe_get(base.rstrip("/") + path, req=req, timeout=4)
        if r and ("dns-message" in r.headers.get("content-type", "").lower() or
                  r.status_code in (200, 400)):
            ct = r.headers.get("content-type", "")
            if "dns" in ct.lower():
                findings.append(wrap_finding(
                    "DNS-over-HTTPS endpoint exposed — potential DoH-tunnel covert channel.",
                    "MEDIUM", cvss="5.0", cwe="CWE-693", owasp="A05:2021",
                    remediation="If unintended, block /dns-query at WAF; if intended, rate-limit and log.",
                    evidence_marker=f"Endpoint {path} returned content-type {ct}"))
                intel["doh_endpoint"] = path
                break
    if not findings:
        findings.append(wrap_finding(
            "No DoH endpoint detected on /dns-query or /resolve.",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Periodically scan for newly-deployed DoH endpoints.",
            evidence_marker="Negative web probe"))
    return _resp("doh_tunnel_fingerprint", req.target, findings, tested=2,
                 what_checked="DoH endpoint exposure check", raw=intel)


@router.post("/api/tunnel/ptunnel_advisory")
def ptunnel_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("ptunnel_advisory", req.target,
        "ptunnel — TCP-over-ICMP echo.",
        sev="MEDIUM", cvss="5.5",
        remediation="Block outbound ICMP echo at egress firewall; if allowed, rate-limit + payload-length cap.")


@router.post("/api/tunnel/hans_advisory")
def hans_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("hans_advisory", req.target,
        "hans — IP-over-ICMP tunnel.",
        sev="MEDIUM", cvss="5.5",
        remediation="Default-deny outbound ICMP except monitored ping-checks.")


@router.post("/api/tunnel/icmp_tunnel_advisory")
def icmp_tunnel_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("icmp_tunnel_advisory", req.target,
        "icmp-tunnel — covert channel via ICMP type 8 payload.",
        sev="MEDIUM", cvss="5.5",
        remediation="ICMP payload-length anomaly detection (>32 bytes); JA-style ICMP fingerprinting.")


@router.post("/api/tunnel/manual_covert_channel_advisory")
def manual_covert_channel_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("manual_covert_channel_advisory", req.target,
        "Manual creative covert channel — analyst-only.",
        sev="INFO", cvss="0.0", cwe="N/A",
        remediation="See Manual Tests panel.")


# ═══════════════ §4 — HTTP / HTTPS Tunneling (8) ═══════════════

@router.post("/api/tunnel/http_connect_probe")
def http_connect_probe(req: ScanRequest, _=Depends(verify_scan_quota)):
    """Live probe: does the target permit HTTP CONNECT to arbitrary host:port?"""
    host = _host(req.target)
    findings, intel = [], {}
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(5)
            if s.connect_ex((host, 80)) != 0:
                findings.append(wrap_finding(
                    "Port 80 not reachable — HTTP CONNECT probe skipped.",
                    "INFO", cvss="0.0", cwe="N/A",
                    remediation="Test against actual web proxy port (3128, 8080).",
                    evidence_marker="80/tcp closed"))
            else:
                s.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
                resp = s.recv(512).decode("utf-8", errors="ignore")
                intel["connect_response"] = resp[:200]
                if "200" in resp.split("\r\n", 1)[0]:
                    findings.append(wrap_finding(
                        "Open HTTP CONNECT proxy — arbitrary egress relay.",
                        "HIGH", cvss="7.5", cwe="CWE-441", owasp="A05:2021",
                        remediation="Disable CONNECT method or restrict to internal allow-list.",
                        evidence_marker=f"Server responded: {resp[:80]}"))
                else:
                    findings.append(wrap_finding(
                        "HTTP CONNECT rejected (good).",
                        "POSITIVE", cvss="0.0", cwe="N/A",
                        remediation="Continue to enforce method restrictions.",
                        evidence_marker=f"Server responded: {resp[:80]}"))
    except Exception as e:
        findings.append(wrap_finding(
            f"HTTP CONNECT probe error: {e}",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Retry from a different perspective; check WAF interference.",
            evidence_marker=str(e)[:80]))
    return _resp("http_connect_probe", req.target, findings,
                 tested=1, what_checked="HTTP CONNECT method support",
                 raw=intel)


@router.post("/api/tunnel/regeorg_signature_probe")
def regeorg_signature_probe(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target)
    findings = []
    # Probe common reGeorg endpoints
    sigs = ["/tunnel.php", "/tunnel.jsp", "/tunnel.aspx", "/cmd.php", "/shell.jsp"]
    for path in sigs:
        r = safe_get(base.rstrip("/") + path, req=req, timeout=3)
        if r and r.status_code == 200 and len(r.text or "") > 0:
            findings.append(wrap_finding(
                f"reGeorg/Neo-reGeorg/Pivotnacci webshell signature: {path}",
                "CRITICAL", cvss="9.0", cwe="CWE-94", owasp="A03:2021",
                remediation="Remove webshell immediately + audit upload paths + check for persistence.",
                evidence_marker=f"GET {path} → 200"))
    if not findings:
        findings.append(wrap_finding(
            "No reGeorg/Neo-reGeorg/Pivotnacci webshell signatures present.",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Schedule periodic webshell signature sweeps.",
            evidence_marker="No matching paths returned 200"))
    return _resp("regeorg_signature_probe", req.target, findings,
                 tested=len(sigs),
                 what_checked="Webshell-tunnel filename signature probes")


@router.post("/api/tunnel/corkscrew_advisory")
def corkscrew_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("corkscrew_advisory", req.target,
        "corkscrew — SSH-over-HTTPS via CONNECT proxy.",
        sev="MEDIUM", cvss="5.0",
        remediation="If CONNECT must be allowed, restrict to allow-listed destination ports/hosts.")


@router.post("/api/tunnel/stunnel_https_advisory")
def stunnel_https_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("stunnel_https_advisory", req.target,
        "stunnel wrapping arbitrary protocol in HTTPS.",
        sev="MEDIUM", cvss="5.0",
        remediation="JA3/JA4 outbound TLS fingerprinting; alert on uncommon TLS fingerprints to public IPs.")


@router.post("/api/tunnel/chisel_http2_fallback_advisory")
def chisel_http2_fallback_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("chisel_http2_fallback_advisory", req.target,
        "Chisel HTTP/2 fallback mode — bypasses strict HTTP/1.1 inspection.",
        sev="HIGH", cvss="7.0",
        remediation="WAF must support full HTTP/2 stream inspection; degrade non-HTTP/2 traffic to HTTP/1.1.")


@router.post("/api/tunnel/frp_https_advisory")
def frp_https_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("frp_https_advisory", req.target,
        "frp HTTPS mode — domain-fronted reverse proxy.",
        sev="HIGH", cvss="7.0",
        remediation="Validate SNI ↔ destination IP at egress; block domain fronting via TLS inspection.")


@router.post("/api/tunnel/cloudfront_fronted_https_advisory")
def cloudfront_fronted_https_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("cloudfront_fronted_https_advisory", req.target,
        "Custom HTTPS C2 tunnel with CloudFront / Azure Front Door domain fronting.",
        sev="HIGH", cvss="7.5",
        remediation="Disable cross-domain fronting on CDNs (AWS / Azure tightened in 2023+); enforce SNI alignment.")


@router.post("/api/tunnel/manual_http_tunnel_advisory")
def manual_http_tunnel_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("manual_http_tunnel_advisory", req.target,
        "Manual creative HTTP tunnel — analyst-only.",
        sev="INFO", cvss="0.0", cwe="N/A",
        remediation="See Manual Tests panel.")


# ═══════════════ §5 — Modern Tunneling (WireGuard / QUIC) (10) ═══════════════

@router.post("/api/tunnel/wireguard_userspace_probe")
def wireguard_userspace_probe(req: ScanRequest, _=Depends(verify_scan_quota)):
    """Probe UDP 51820 (WireGuard default)."""
    host = _host(req.target)
    findings = []
    open51820 = _udp_listen(host, 51820, timeout=2.0)
    if open51820:
        findings.append(wrap_finding(
            "UDP/51820 (WireGuard default) is reachable — likely WireGuard endpoint exposed.",
            "MEDIUM", cvss="5.0", cwe="CWE-1395", owasp="A05:2021",
            remediation="If intentional, restrict source IPs; if not, close at firewall.",
            evidence_marker="UDP/51820 sent → no ICMP unreachable (likely open or filtered)."))
    else:
        findings.append(wrap_finding(
            "UDP/51820 not reachable — WireGuard default port closed.",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue blocking non-essential UDP at edge.",
            evidence_marker="UDP/51820 ICMP unreachable received."))
    return _resp("wireguard_userspace_probe", req.target, findings,
                 tested=1, what_checked="WireGuard default UDP port 51820")


@router.post("/api/tunnel/tailscale_lateral_probe")
def tailscale_lateral_probe(req: ScanRequest, _=Depends(verify_scan_quota)):
    """Probe Tailscale port (UDP 41641 / TCP 41641) plus magic DNS .ts.net presence."""
    host = _host(req.target)
    findings = []
    tcp41641 = _tcp_open(host, 41641, timeout=2.0)
    if tcp41641 or host.endswith(".ts.net"):
        findings.append(wrap_finding(
            "Tailscale surface detected (port 41641 or .ts.net hostname).",
            "MEDIUM", cvss="5.0", cwe="CWE-1395",
            remediation="Audit Tailscale ACLs; enable lock + key expiry; review user device list.",
            evidence_marker=f"TCP/41641={tcp41641}; host={host}"))
    else:
        findings.append(wrap_finding(
            "No Tailscale fingerprint detected.",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue periodic mesh-VPN inventory.",
            evidence_marker="TCP/41641 closed; hostname is not .ts.net"))
    return _resp("tailscale_lateral_probe", req.target, findings, tested=2,
                 what_checked="Tailscale port + hostname fingerprint")


@router.post("/api/tunnel/zerotier_lateral_probe")
def zerotier_lateral_probe(req: ScanRequest, _=Depends(verify_scan_quota)):
    """Probe ZeroTier UDP 9993."""
    host = _host(req.target)
    findings = []
    open9993 = _udp_listen(host, 9993, timeout=2.0)
    if open9993:
        findings.append(wrap_finding(
            "ZeroTier UDP/9993 reachable — mesh-VPN endpoint exposed.",
            "MEDIUM", cvss="5.0", cwe="CWE-1395",
            remediation="Audit ZeroTier network controllers + members; rotate network ID if compromised.",
            evidence_marker="UDP/9993 likely open."))
    else:
        findings.append(wrap_finding(
            "ZeroTier UDP/9993 not reachable.",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue mesh-VPN inventory.",
            evidence_marker="UDP/9993 closed."))
    return _resp("zerotier_lateral_probe", req.target, findings, tested=1,
                 what_checked="ZeroTier default port 9993")


@router.post("/api/tunnel/cloudflared_fingerprint")
def cloudflared_fingerprint(req: ScanRequest, _=Depends(verify_scan_quota)):
    """Detect Cloudflare-Tunnel-backed origins via CF-RAY header + server fingerprint."""
    base = web_url(req.target)
    findings, intel = [], {}
    r = safe_get(base, req=req, timeout=5)
    if r:
        cf_ray = r.headers.get("cf-ray", "")
        srv = r.headers.get("server", "")
        intel["cf_ray"] = cf_ray
        intel["server"] = srv
        if cf_ray and "cloudflare" in srv.lower():
            findings.append(wrap_finding(
                "Cloudflare-fronted origin — could be Cloudflare Tunnel (cloudflared) backend.",
                "INFO", cvss="0.0", cwe="N/A",
                remediation="Cloudflare Tunnel is legitimate; ensure tunnel ACLs + WARP routing policies.",
                evidence_marker=f"CF-Ray: {cf_ray}; Server: {srv}"))
        else:
            findings.append(wrap_finding(
                "Origin does not appear to be Cloudflare-fronted.",
                "INFO", cvss="0.0", cwe="N/A",
                remediation="Continue periodic origin-fronting inventory.",
                evidence_marker=f"No CF-Ray header"))
    else:
        findings.append(wrap_finding(
            "Could not retrieve response.",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Retry from a different perspective.",
            evidence_marker="No HTTP response"))
    return _resp("cloudflared_fingerprint", req.target, findings, tested=1,
                 what_checked="Cloudflare Tunnel fingerprint via headers",
                 raw=intel)


@router.post("/api/tunnel/ngrok_localtunnel_fingerprint")
def ngrok_localtunnel_fingerprint(req: ScanRequest, _=Depends(verify_scan_quota)):
    """Detect Ngrok / localtunnel by hostname pattern + server header."""
    host = _host(req.target)
    findings, intel = [], {"host": host}
    is_ngrok = any(host.endswith(suf) for suf in (".ngrok.io", ".ngrok-free.app", ".ngrok.app"))
    is_localtunnel = host.endswith(".loca.lt") or host.endswith(".localtunnel.me")
    if is_ngrok or is_localtunnel:
        kind = "Ngrok" if is_ngrok else "localtunnel"
        findings.append(wrap_finding(
            f"{kind} ad-hoc tunnel hostname detected — production traffic should not route through this.",
            "HIGH", cvss="7.0", cwe="CWE-693", owasp="A05:2021",
            remediation="Block *.ngrok.io / *.loca.lt at proxy egress; audit endpoint asset inventory.",
            evidence_marker=f"hostname matches {kind} pattern"))
    else:
        findings.append(wrap_finding(
            "No Ngrok / localtunnel hostname pattern.",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue periodic ad-hoc-tunnel hostname sweeps.",
            evidence_marker=f"hostname: {host}"))
    return _resp("ngrok_localtunnel_fingerprint", req.target, findings, tested=1,
                 what_checked="Ngrok / localtunnel hostname patterns",
                 raw=intel)


@router.post("/api/tunnel/quic_http3_advisory")
def quic_http3_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("quic_http3_advisory", req.target,
        "QUIC / HTTP3 tunnel — covert channel via UDP/443.",
        sev="MEDIUM", cvss="5.0",
        remediation="QUIC-aware NSM (Zeek 5+) for HTTP/3 metadata; SNI inspection at egress.")


@router.post("/api/tunnel/lightway_advisory")
def lightway_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("lightway_advisory", req.target,
        "Lightway VPN — ExpressVPN's wolfSSL-based protocol.",
        sev="MEDIUM", cvss="5.0",
        remediation="JA3/JA4 fingerprint outbound TLS; alert on Lightway-specific signatures.")


@router.post("/api/tunnel/manual_wg_config_exfil_advisory")
def manual_wg_config_exfil_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("manual_wg_config_exfil_advisory", req.target,
        "Manual WireGuard config exfiltration — analyst-only.",
        sev="INFO", cvss="0.0", cwe="N/A",
        remediation="See Manual Tests panel.")


@router.post("/api/tunnel/manual_tailscale_acl_bypass_advisory")
def manual_tailscale_acl_bypass_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("manual_tailscale_acl_bypass_advisory", req.target,
        "Manual Tailscale ACL bypass — analyst-only.",
        sev="INFO", cvss="0.0", cwe="N/A",
        remediation="See Manual Tests panel.")


@router.post("/api/tunnel/manual_vpn_pivot_chain_advisory")
def manual_vpn_pivot_chain_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return _adv("manual_vpn_pivot_chain_advisory", req.target,
        "Manual creative VPN-pivot chain — analyst-only.",
        sev="INFO", cvss="0.0", cwe="N/A",
        remediation="See Manual Tests panel.")


def register(app):
    app.include_router(router)
