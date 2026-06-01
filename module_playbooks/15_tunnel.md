# Port Redirection & Tunneling — Master Reference (`tunnel_ruff`)

**100% Full Industry Standard catalogue.** Companion to `pivot_ruff.md` (heavy overlap — this focuses on the tunneling primitives).

5 sections, 50 techniques. auto · manual · NEW 2024+

---

## Summary

| § | Section | Techniques | Auto | Manual |
|---|---|---|---|---|
| 1 | SSH Tunnel Primitives | 10 | 10 | 0 |
| 2 | Reverse Tunneling Tools | 12 | 11 | 1 |
| 3 | DNS / ICMP Tunneling | 8 | 7 | 1 |
| 4 | HTTP / HTTPS Tunneling | 8 | 7 | 1 |
| 5 | Modern Tunneling (WireGuard / QUIC) | 10 | 7 | 3 |
| **TOTAL** | | **48** | **42** | **6** |

---

## §1 — SSH Tunnel Primitives
1 SSH local port forward (-L) · 2 SSH remote port forward (-R) · 3 SSH dynamic SOCKS5 (-D) · 4 SSH ProxyJump (-J) · 5 SSH ProxyCommand · 6 sshuttle · 7 ssh -N -f detached · 8 SSH config Match host · 9 SSH agent forward (-A) · 10 OpenSSH built-in SOCKS

## §2 — Reverse Tunneling Tools
11 Chisel · 12 Ligolo-ng (TUN-based, fastest) · 13 Rsockstun · 14 socat · 15 ncat (with --listen) · 16 plink (Windows) · 17 frp (fast reverse proxy) · 18 reGeorg (legacy webshell tunnel) · 19 Neo-reGeorg · 20 Pivotnacci · 21 stunnel TLS wrapper · 22 Manual creative tunnel chain

## §3 — DNS / ICMP Tunneling
23 dnscat2 · 24 iodine · 25 DNStunnel · 26 DNS-over-HTTPS tunnel · 27 ptunnel (ICMP) · 28 hans (IP-over-ICMP) · 29 icmp-tunnel · 30 Manual creative covert channel

## §4 — HTTP / HTTPS Tunneling
31 HTTP CONNECT proxy · 32 reGeorg/Neo-reGeorg/Pivotnacci · 33 corkscrew (HTTPS) · 34 stunnel TLS · 35 chisel (HTTP/2 fallback) · 36 frp HTTP/HTTPS mode · 37 Custom HTTPS C2 tunnel (cloudfront fronting) · 38 Manual creative HTTP tunnel

## §5 — Modern Tunneling (WireGuard / QUIC) NEW
39 WireGuard userspace tunnel · 40 Tailscale lateral abuse · 41 ZeroTier lateral · 42 Cloudflare Tunnel (cloudflared) · 43 Ngrok / localtunnel ad-hoc · 44 QUIC tunnel (HTTP/3 fronting) · 45 Lightway VPN protocol · 46 Manual WireGuard config exfil · 47 Manual Tailscale ACL bypass · 48 Manual creative VPN-pivot chain

---

## VulnusLab Status
- SOON (module #14) · Planned: Chisel Tunnel, Socat Relay, SSH PF, Proxychains Config, Ligolo-ng
- Coverage: ~0%

## References
- Chisel · Ligolo-ng · frp · sshuttle · dnscat2 · iodine · Tailscale · Cloudflare Tunnel
