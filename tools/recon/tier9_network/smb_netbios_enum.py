"""SMB/NetBIOS Enum v2 — VL-FORGE. TCP 139/445 + UDP 137 probe."""
import asyncio, socket
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
def _tcp(ip,port,timeout=3):
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip,port))==0
    except: return False
def _nbns(ip,timeout=3):
    payload=b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.settimeout(timeout); s.sendto(payload,(ip,137))
            data,_=s.recvfrom(2048)
            return len(data)>0
    except: return False
async def gather(ctx):
    ips=await _resolve(ctx.host)
    if not ips: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["ip"]=ips[0]
    res445,res139,res137=await asyncio.gather(
        asyncio.to_thread(_tcp,ips[0],445),
        asyncio.to_thread(_tcp,ips[0],139),
        asyncio.to_thread(_nbns,ips[0]))
    if res445: ctx.source("smb-445")
    if res139: ctx.source("netbios-139")
    if res137: ctx.source("nbns-137")
    ctx.state.update({"smb_445":res445,"netbios_139":res139,"nbns_137":res137,
        "exposed":res445 or res139 or res137})
def _r_exposed(s):
    if not s.get("exposed"): return None
    ports=[];
    if s.get("smb_445"): ports.append("445/SMB")
    if s.get("netbios_139"): ports.append("139/NetBIOS")
    if s.get("nbns_137"): ports.append("137/NBNS")
    return {"name":f"SMB/NetBIOS exposed to internet ({', '.join(ports)})","severity":"HIGH","cvss":7.5,
        "cwe":"CWE-200","owasp":"A05:2021",
        "evidence":", ".join(ports),
        "remediation":"Block SMB/NetBIOS at perimeter firewall. Never expose to internet — ransomware vector."}
FINDING_RULES=[_r_exposed]
INTEL_FIELDS=[("IP","ip"),("SMB 445","smb_445"),("NetBIOS 139","netbios_139"),("NBNS 137","nbns_137")]
@router.post("/api/recon/smb_netbios_enum")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="smb_netbios_enum",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["smb_445","netbios_139","nbns_137"])
def register(app): app.include_router(router)
