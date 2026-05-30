"""Port Redirection & Tunneling module — module_playbooks/15_tunnel.md.

48 techniques across 5 sections. Most are post-compromise primitives
(an attacker uses them AFTER access). For SaaS pentest scanning the
catalogue is rendered as:

  - LIVE detection probes — what's externally observable
    (SSH banner / version, HTTP CONNECT method, DoH endpoints,
    Cloudflare-Tunnel cdn fingerprints, Ngrok subdomain, WireGuard /
    Tailscale / ZeroTier UDP ports, frp & chisel response signatures).

  - ADVISORY entries — analyst-grade reference findings the customer's
    blue team can verify against their EDR/NSM logs (technique +
    detection guidance + remediation), shipped as structured findings
    rather than empty stubs.

  - MANUAL technique cards — rendered in the Manual Tests panel for
    analyst-attested execution.

Single-pack module: one Python file (`tunnel_pack.py`) registers all
endpoints under `/api/tunnel/<tool>`.
"""
