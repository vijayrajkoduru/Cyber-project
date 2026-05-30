"""Tunneling module orchestrator — built 2026-05-30 from 15_tunnel.md.

48 endpoints under POST /api/tunnel/<tool>. Streaming NDJSON via run_all.
"""
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from tools._shared import verify_scan_quota
from tools._framework.orchestrator import (run_module_parallel, run_module_streaming)

router = APIRouter()


TUNNEL_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_ssh_primitives": [
        ("ssh_local_forward_advisory",   "/api/tunnel/ssh_local_forward_advisory"),
        ("ssh_remote_forward_advisory",  "/api/tunnel/ssh_remote_forward_advisory"),
        ("ssh_dynamic_socks5_advisory",  "/api/tunnel/ssh_dynamic_socks5_advisory"),
        ("ssh_proxyjump_advisory",       "/api/tunnel/ssh_proxyjump_advisory"),
        ("ssh_proxycommand_advisory",    "/api/tunnel/ssh_proxycommand_advisory"),
        ("sshuttle_advisory",            "/api/tunnel/sshuttle_advisory"),
        ("ssh_detached_advisory",        "/api/tunnel/ssh_detached_advisory"),
        ("ssh_config_match_advisory",    "/api/tunnel/ssh_config_match_advisory"),
        ("ssh_agent_forward_advisory",   "/api/tunnel/ssh_agent_forward_advisory"),
        ("openssh_socks_advisory",       "/api/tunnel/openssh_socks_advisory"),
    ],
    "tier2_reverse_tools": [
        ("chisel_fingerprint",           "/api/tunnel/chisel_fingerprint"),
        ("ligolo_ng_advisory",           "/api/tunnel/ligolo_ng_advisory"),
        ("rsockstun_advisory",           "/api/tunnel/rsockstun_advisory"),
        ("socat_advisory",               "/api/tunnel/socat_advisory"),
        ("ncat_listen_advisory",         "/api/tunnel/ncat_listen_advisory"),
        ("plink_advisory",               "/api/tunnel/plink_advisory"),
        ("frp_fingerprint",              "/api/tunnel/frp_fingerprint"),
        ("regeorg_advisory",             "/api/tunnel/regeorg_advisory"),
        ("neo_regeorg_advisory",         "/api/tunnel/neo_regeorg_advisory"),
        ("pivotnacci_advisory",          "/api/tunnel/pivotnacci_advisory"),
        ("stunnel_advisory",             "/api/tunnel/stunnel_advisory"),
        ("manual_creative_tunnel_chain_advisory",
                                         "/api/tunnel/manual_creative_tunnel_chain_advisory"),
    ],
    "tier3_dns_icmp": [
        ("dnscat2_advisory",             "/api/tunnel/dnscat2_advisory"),
        ("iodine_advisory",              "/api/tunnel/iodine_advisory"),
        ("dnstunnel_advisory",           "/api/tunnel/dnstunnel_advisory"),
        ("doh_tunnel_fingerprint",       "/api/tunnel/doh_tunnel_fingerprint"),
        ("ptunnel_advisory",             "/api/tunnel/ptunnel_advisory"),
        ("hans_advisory",                "/api/tunnel/hans_advisory"),
        ("icmp_tunnel_advisory",         "/api/tunnel/icmp_tunnel_advisory"),
        ("manual_covert_channel_advisory","/api/tunnel/manual_covert_channel_advisory"),
    ],
    "tier4_http_https": [
        ("http_connect_probe",           "/api/tunnel/http_connect_probe"),
        ("regeorg_signature_probe",      "/api/tunnel/regeorg_signature_probe"),
        ("corkscrew_advisory",           "/api/tunnel/corkscrew_advisory"),
        ("stunnel_https_advisory",       "/api/tunnel/stunnel_https_advisory"),
        ("chisel_http2_fallback_advisory","/api/tunnel/chisel_http2_fallback_advisory"),
        ("frp_https_advisory",           "/api/tunnel/frp_https_advisory"),
        ("cloudfront_fronted_https_advisory",
                                         "/api/tunnel/cloudfront_fronted_https_advisory"),
        ("manual_http_tunnel_advisory",  "/api/tunnel/manual_http_tunnel_advisory"),
    ],
    "tier5_modern": [
        ("wireguard_userspace_probe",    "/api/tunnel/wireguard_userspace_probe"),
        ("tailscale_lateral_probe",      "/api/tunnel/tailscale_lateral_probe"),
        ("zerotier_lateral_probe",       "/api/tunnel/zerotier_lateral_probe"),
        ("cloudflared_fingerprint",      "/api/tunnel/cloudflared_fingerprint"),
        ("ngrok_localtunnel_fingerprint","/api/tunnel/ngrok_localtunnel_fingerprint"),
        ("quic_http3_advisory",          "/api/tunnel/quic_http3_advisory"),
        ("lightway_advisory",            "/api/tunnel/lightway_advisory"),
        ("manual_wg_config_exfil_advisory","/api/tunnel/manual_wg_config_exfil_advisory"),
        ("manual_tailscale_acl_bypass_advisory",
                                         "/api/tunnel/manual_tailscale_acl_bypass_advisory"),
        ("manual_vpn_pivot_chain_advisory","/api/tunnel/manual_vpn_pivot_chain_advisory"),
    ],
}


class TunnelRunAllRequest(BaseModel):
    target: str
    concurrency: Optional[int] = 16
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None


def _all_tools() -> list[tuple[str, str]]:
    out = []
    for tools in TUNNEL_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


def _resolve(req: "TunnelRunAllRequest", request: Request):
    tools = _all_tools()
    extra = None
    jwt_token = request.headers.get("authorization", "").replace("Bearer ", "") or None
    return tools, extra, jwt_token


@router.post("/api/tunnel/run_all")
async def tunnel_run_all(req: "TunnelRunAllRequest",
                         request: Request,
                         _=Depends(verify_scan_quota)):
    tools, extra, jwt_token = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 16, 32))
    generator = run_module_streaming(
        target=req.target,
        tools=tools,
        module_name="tunnel",
        concurrency=concurrency,
        auth_cookie=req.auth_cookie,
        auth_bearer=req.auth_bearer,
        extra_body=extra,
        jwt_token=jwt_token,
    )
    return StreamingResponse(
        generator,
        media_type="application/x-ndjson",
        headers={
            "X-Accel-Buffering": "no",
            "Cache-Control":     "no-store, no-transform",
            "Connection":        "keep-alive",
        },
    )


@router.get("/api/tunnel/run_all/tiers")
async def tunnel_run_all_tiers():
    return {
        "tiers": [
            {"id": tier_id, "tools": [name for name, _ in tools],
              "count": len(tools)}
            for tier_id, tools in TUNNEL_TOOLS_BY_TIER.items()
        ],
        "total_tools": sum(len(t) for t in TUNNEL_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
