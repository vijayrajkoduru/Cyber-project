"""IPMI/iLO Discovery v2 — VL-FORGE. UDP 623 + HTTPS management interfaces."""
import asyncio, socket, requests
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
async def _resolve(h):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4
        return [str(x).rstrip(".") for x in await r.resolve(h,"A")]
    except: return []
def _ipmi_probe(ip,timeout=3):
    payload=b"\x06\x00\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x20\x18\xc8\x81\x00\x38\x8e\x04\xb5"
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.settimeout(timeout); s.sendto(payload,(ip,623))
            data,_=s.recvfrom(2048)
            return len(data)>0
    except: return False
def _http_probe(ip,paths):
    found=[]
    for path in paths:
        try:
            r=requests.get(f"https://{ip}{path}",timeout=4,verify=False,
                headers={"User-Agent":"VulnusLab/1.0"},allow_redirects=False)
            if r.status_code in (200,302) and any(k in (r.text or "").lower()[:2000] for k in ["ilo","ipmi","drac","supermicro","redfish"]):
                found.append({"path":path,"status":r.status_code,"size":len(r.content)})
        except: pass
    return found
async def gather(ctx):
    ips=await _resolve(ctx.host)
    if not ips: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["ip"]=ips[0]
    ipmi,redfish=await asyncio.gather(
        asyncio.to_thread(_ipmi_probe,ips[0]),
        asyncio.to_thread(_http_probe,ips[0],["/redfish/v1/","/ilo","/cgi/url_redirect.cgi","/IPMI"]))
    if ipmi: ctx.source("ipmi-623")
    if redfish: ctx.source("mgmt-interface")
    ctx.state.update({"ipmi_udp_623":ipmi,"mgmt_interfaces":redfish,
        "mgmt_exposed":ipmi or bool(redfish)})
def _r_exposed(s):
    if not s.get("mgmt_exposed"): return None
    reasons=[]
    if s.get("ipmi_udp_623"): reasons.append("IPMI/623")
    if s.get("mgmt_interfaces"): reasons.append(f"{len(s['mgmt_interfaces'])} mgmt URL(s)")
    return {"name":"Out-of-band management exposed","severity":"CRITICAL","cvss":9.5,
        "cwe":"CWE-668","owasp":"A05:2021",
        "evidence":"; ".join(reasons),
        "remediation":"IPMI/iLO/iDRAC should NEVER be internet-exposed. Firewall to trusted bastion."}
FINDING_RULES=[_r_exposed]
INTEL_FIELDS=[("IP","ip"),("IPMI 623","ipmi_udp_623"),("Mgmt URLs","mgmt_interfaces")]
@router.post("/api/recon/ipmi_ilo_discovery")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="ipmi_ilo_discovery",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["ipmi_udp_623","mgmt_interfaces","mgmt_exposed"])
def register(app): app.include_router(router)
