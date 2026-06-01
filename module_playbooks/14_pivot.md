# Pivoting & Lateral Movement — Master Reference (`pivot_ruff`)

**100% Full Industry Standard catalogue** — MITRE ATT&CK TA0008 Lateral Movement + Chisel/Ligolo canon.

6 sections, 60 techniques. auto · (probe) · manual · NEW 2024+

---

## Summary

| § | Section | Techniques | Auto | Manual |
|---|---|---|---|---|
| 1 | SSH-based Tunneling | 10 | 10 | 0 |
| 2 | SOCKS / HTTP Proxy Pivot | 10 | 9 | 1 |
| 3 | Reverse Tunnel Tools | 10 | 9 | 1 |
| 4 | Windows Lateral Movement | 12 | 11 | 1 |
| 5 | Linux Lateral Movement | 8 | 7 | 1 |
| 6 | Modern Cloud Pivot | 10 | 7 | 3 |
| **TOTAL** | | **60** | **53** | **7** |

---

## §1 — SSH-based Tunneling
1 SSH local port forward (-L) · 2 SSH remote port forward (-R) · 3 SSH dynamic SOCKS5 (-D) · 4 SSH ProxyJump multi-hop · 5 SSH ProxyCommand · 6 sshuttle "poor man's VPN" · 7 SSH key reuse for pivot · 8 SSH config auto-pivot · 9 SSH agent forwarding abuse · 10 OpenSSH built-in SOCKS

## §2 — SOCKS / HTTP Proxy Pivot
11 proxychains config · 12 proxychains-ng (multi-chain) · 13 SOCKS over Meterpreter · 14 Burp upstream proxy · 15 Web proxy via reGeorg · 16 PHP reGeorg / Neo-reGeorg · 17 ASPX reGeorg · 18 JSP reGeorg · 19 manual creative proxy chain · 20 HTTP/2 over SOCKS proxy

## §3 — Reverse Tunnel Tools
21 Chisel client/server · 22 Chisel reverse tunnel · 23 Ligolo-ng modern tunnel · 24 Rsockstun · 25 socat relay · 26 ncat relay · 27 plink (Windows) port forward · 28 stunnel TLS wrapper · 29 Meterpreter route + portfwd · 30 Manual creative tunnel chain

## §4 — Windows Lateral Movement
31 PsExec (Sysinternals + impacket) · 32 WMIExec · 33 SMBExec · 34 AtExec (task scheduler) · 35 DCOMExec · 36 WinRM (evil-winrm) · 37 RDP hijack via tscon · 38 RDP session-takeover · 39 PSRemoting / Invoke-Command · 40 Crackmapexec / NetExec swiss-army · 41 SCCM lateral via NAA cred · 42 Manual creative lateral chain

## §5 — Linux Lateral Movement
43 SSH key reuse · 44 SSH agent socket abuse · 45 RPC / NFS share lateral · 46 Docker socket pivot · 47 Kubernetes kubectl from pod · 48 systemd cross-host abuse · 49 Manual creative Linux pivot · 50 cross-platform Salt/Ansible pivot

## §6 — Modern Cloud Pivot NEW
51 AWS STS AssumeRole chain · 52 Azure managed identity → cross-tenant · 53 GCP impersonate service account · 54 EKS pod → IRSA → AWS account · 55 GKE workload identity → GCP project · 56 OIDC trust → cross-cloud pivot · 57 Cross-account S3/STS pivot · 58 Cross-tenant Azure AD pivot · 59 Manual creative cloud chain · 60 Manual hybrid identity pivot

---

## VulnusLab Status
- SOON (module #12) · Planned: SSH Local PF, SSH SOCKS5, Chisel Reverse, Proxychains, Ligolo-ng
- Coverage: ~0%

## References
- Chisel: https://github.com/jpillora/chisel · Ligolo-ng: https://github.com/nicocha30/ligolo-ng · sshuttle: https://github.com/sshuttle/sshuttle · CloudFox: https://github.com/BishopFox/cloudfox · NetExec: https://github.com/Pennyw0rth/NetExec
