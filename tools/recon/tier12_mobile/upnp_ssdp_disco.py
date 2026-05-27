"""upnp_ssdp_disco — VL-FORGE Recon (real, zero-FP)."""
import asyncio, os, re, json, urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._osint_helpers import get_json, get_text


router = APIRouter()

async def gather(ctx: ScanContext):
    # SSDP is multicast LAN-scoped; pure-Python remote probe is limited.
    # We can attempt unicast M-SEARCH against the target's IP if firewall permits.
    from tools.recon._network_helpers import udp_probe, resolve_host
    ip = resolve_host(ctx.host)
    if not ip:
        ctx.state["unresolved"] = True; ctx.source("DNS"); return
    pkt = (b"M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nMan: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n")
    r = await udp_probe(ip, 1900, pkt, timeout=4)
    responding = bool(r and b"HTTP/1.1 200" in r)
    ctx.state["ssdp_responding"] = responding
    ctx.state["banner"] = r[:300].decode("utf-8","ignore") if r else ""
    ctx.source("Unicast SSDP M-SEARCH on UDP 1900")

RULES = [
    lambda s: {"name":"UPnP/SSDP responder exposed (UDP 1900)","severity":"MEDIUM",
        "evidence":f"SSDP banner: {s.get('banner')[:200]}",
        "remediation":"Block UDP 1900 inbound. Disable UPnP on router. Prevents amplification + device enum.",
        "cwe":"CWE-668","owasp":"A05:2021"
    } if s.get("ssdp_responding") else None,
]

@router.post("/api/recon/upnp_ssdp_disco")
async def recon_upnp_ssdp_disco(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="upnp_ssdp_disco",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("SSDP Responding","ssdp_responding"),("Banner","banner")])

def register(app):
    app.include_router(router)
