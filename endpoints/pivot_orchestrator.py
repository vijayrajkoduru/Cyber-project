"""Pivot module orchestrator — 14_pivot.md (60 endpoints)."""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_parallel, run_module_streaming

router = APIRouter()

PIVOT_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_ssh": [(n, f"/api/pivot/{n}") for n in [
        "ssh_local_pf_advisory", "ssh_remote_pf_advisory", "ssh_socks5_advisory",
        "ssh_proxyjump_multi_advisory", "ssh_proxycommand_pivot_advisory",
        "sshuttle_pivot_advisory", "ssh_key_reuse_advisory",
        "ssh_config_autopivot_advisory", "ssh_agent_forwarding_abuse_advisory",
        "openssh_socks_advisory"]],
    "tier2_socks_http": [(n, f"/api/pivot/{n}") for n in [
        "proxychains_config", "proxychains_ng_multi", "socks_over_meterpreter",
        "burp_upstream_proxy", "web_proxy_regeorg", "php_regeorg",
        "aspx_regeorg", "jsp_regeorg", "manual_proxy_chain", "http2_socks_proxy"]],
    "tier3_reverse_tunnel": [(n, f"/api/pivot/{n}") for n in [
        "chisel_pivot_client_server", "chisel_reverse_tunnel", "ligolo_ng_modern_pivot",
        "rsockstun_pivot", "socat_relay_pivot", "ncat_relay_pivot", "plink_pivot",
        "stunnel_pivot", "meterpreter_route_portfwd", "manual_pivot_chain"]],
    "tier4_windows_lateral": [(n, f"/api/pivot/{n}") for n in [
        "psexec_probe", "wmiexec_probe", "smbexec_probe", "atexec_advisory",
        "dcomexec_advisory", "winrm_probe", "rdp_hijack_tscon_advisory",
        "rdp_session_takeover_probe", "psremoting_advisory",
        "crackmapexec_netexec_advisory", "sccm_naa_advisory",
        "manual_windows_lateral_advisory"]],
    "tier5_linux_lateral": [(n, f"/api/pivot/{n}") for n in [
        "ssh_key_reuse_linux", "ssh_agent_socket_abuse", "rpc_nfs_share_lateral",
        "docker_socket_pivot", "kubectl_pod_pivot", "systemd_cross_host_advisory",
        "manual_linux_pivot", "salt_ansible_pivot"]],
    "tier6_cloud_pivot": [(n, f"/api/pivot/{n}") for n in [
        "aws_sts_assumerole_chain", "azure_managed_id_cross_tenant",
        "gcp_impersonate_sa", "eks_irsa_to_aws_account",
        "gke_workload_identity_pivot", "oidc_trust_cross_cloud",
        "cross_account_s3_sts_pivot", "cross_tenant_azure_ad_pivot",
        "manual_cloud_chain", "manual_hybrid_identity_pivot"]],
}


class PivotRunAllRequest(BaseModel):
    target: str
    concurrency: Optional[int] = 16
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None


def _all_tools():
    out = []
    for tools in PIVOT_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


@router.post("/api/pivot/run_all")
async def pivot_run_all(req: PivotRunAllRequest, request: Request,
                         _=Depends(verify_scan_quota)):
    jwt_token = request.headers.get("authorization", "").replace("Bearer ", "") or None
    generator = run_module_streaming(target=req.target, tools=_all_tools(),
        module_name="pivot", concurrency=max(1, min(req.concurrency or 16, 32)),
        auth_cookie=req.auth_cookie, auth_bearer=req.auth_bearer,
        extra_body=None, jwt_token=jwt_token)
    return StreamingResponse(generator, media_type="application/x-ndjson",
        headers={"X-Accel-Buffering":"no", "Cache-Control":"no-store, no-transform",
                 "Connection":"keep-alive"})


@router.get("/api/pivot/run_all/tiers")
async def pivot_run_all_tiers():
    return {"tiers":[{"id":k,"tools":[n for n,_ in t],"count":len(t)}
                     for k,t in PIVOT_TOOLS_BY_TIER.items()],
            "total_tools": sum(len(t) for t in PIVOT_TOOLS_BY_TIER.values())}


def register(app):
    app.include_router(router)
