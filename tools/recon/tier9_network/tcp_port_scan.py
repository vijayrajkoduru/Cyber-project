"""TCP Port Scan v2 — VL-FORGE. Top-100 ports via pure-Python socket."""
import asyncio, socket
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
_TOP_TCP=[21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,
    993,995,1433,1521,1723,2049,2375,2376,3306,3389,5432,5601,5900,5984,
    6379,8000,8080,8443,8888,9000,9200,9300,11211,15672,27017,
    50,80,81,443,873,1080,1194,1414,1900,2082,2083,2086,2087,2096,
    3000,3001,3128,4000,4040,4243,4500,5000,5001,5005,5050,5100,5222,
    5269,5280,5601,5666,5672,5800,5900,5938,5985,5986,6000,6001,6379,
    7001,7002,7070,7080,7443,8000,8001,8009,8081,8086,8090,8161,8181,
    8200,8300,8400,8500,8530,8531,8834,8880,8888,9090,9091,9100,9418,
    9876,9999,10000,10250,10443,11371,15672,17170,17988,19350,20000,
    25565,27017,28017,32768]
async def _resolve(h):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4;r.lifetime=6
        return [str(x).rstrip(".") for x in await r.resolve(h,"A")]
    except Exception: return []
def _probe(ip,port,timeout=2):
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            r=s.connect_ex((ip,port))
            return port if r==0 else None
    except Exception: return None
async def gather(ctx):
    ips=await _resolve(ctx.host)
    if not ips: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["ip_scanned"]=ips[0]
    ctx.source(f"target-{ips[0]}")
    ports=sorted(set(_TOP_TCP))[:100]
    sem=asyncio.Semaphore(50)
    async def one(p):
        async with sem: return await asyncio.to_thread(_probe,ips[0],p)
    res=await asyncio.gather(*[one(p) for p in ports])
    open_ports=sorted([p for p in res if p])
    if open_ports: ctx.source(f"open-{len(open_ports)}")
    ctx.state.update({"open_ports":open_ports,"port_count":len(open_ports),
        "ports_probed":len(ports)})
def _r_dangerous(s):
    risky={21:"FTP",23:"Telnet",1433:"MSSQL",3306:"MySQL",5432:"Postgres",
        27017:"MongoDB",6379:"Redis",9200:"Elasticsearch",2375:"Docker API",
        11211:"Memcached",5984:"CouchDB",5601:"Kibana"}
    open_ports=s.get("open_ports") or []
    hits=[(p,risky[p]) for p in open_ports if p in risky]
    if not hits: return None
    return {"name":f"Dangerous services exposed ({len(hits)})","severity":"CRITICAL","cvss":9.0,
        "cwe":"CWE-668","owasp":"A05:2021",
        "evidence":"; ".join(f"{n} on :{p}" for p,n in hits[:5]),
        "remediation":"Bind to localhost or firewall to trusted IPs. Cleartext + DB services should never face internet."}
def _r_web(s):
    op=s.get("open_ports") or []
    web=[p for p in op if p in (80,443,8080,8443,8000,8443,3000,5000)]
    if not web: return None
    return {"name":f"Web services on {len(web)} port(s)","severity":"INFO",
        "evidence":f"Ports: {web}"}
def _r_count(s):
    n=s.get("port_count",0)
    if n==0: return None
    return {"name":f"{n} open TCP ports","severity":"INFO",
        "evidence":f"Open: {s.get('open_ports')}"}
def _r_clean(s):
    if s.get("port_count",0)>0 or not s.get("reachable"): return None
    return {"name":"No open TCP ports in top-100","severity":"POSITIVE",
        "evidence":f"Probed {s.get('ports_probed',0)} — all closed/filtered"}
FINDING_RULES=[_r_dangerous,_r_web,_r_count,_r_clean]
INTEL_FIELDS=[("Target IP","ip_scanned"),("Open ports","open_ports"),
    ("Open count","port_count"),("Ports probed","ports_probed")]
@router.post("/api/recon/tcp_port_scan")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="tcp_port_scan",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["open_ports","port_count","ip_scanned"])
def register(app): app.include_router(router)
