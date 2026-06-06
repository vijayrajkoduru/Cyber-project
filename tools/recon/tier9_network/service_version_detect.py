"""Service Version Detect v2 — VL-FORGE. Banner-based version fingerprinting."""
import asyncio, socket, re
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
router=APIRouter()
_PROBES={22:b"",80:b"GET / HTTP/1.0\r\n\r\n",443:b"",21:b"",25:b"",110:b"",
    143:b"",6379:b"INFO\r\n",11211:b"version\r\n",27017:b""}
async def _resolve(h):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4
        return [str(x).rstrip(".") for x in await r.resolve(h,"A")]
    except: return []
def _grab(ip,port,payload=b"",timeout=4):
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip,port))
            if payload: s.send(payload)
            return s.recv(4096).decode("utf-8",errors="ignore")
    except: return ""
def _parse_version(banner):
    patterns=[r"OpenSSH[_\- ]([\d.]+)",r"nginx/([\d.]+)",r"Apache/([\d.]+)",
        r"Postfix",r"Microsoft IIS/([\d.]+)",r"Server: ([^\r\n]+)",
        r"redis_version:([\d.]+)",r"VERSION ([\d.]+)"]
    for p in patterns:
        m=re.search(p,banner)
        if m: return m.group(0)[:80]
    return None
async def gather(ctx):
    ips=await _resolve(ctx.host)
    if not ips: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["ip"]=ips[0]
    ctx.source(f"target-{ips[0]}")
    services={}
    for port,payload in _PROBES.items():
        banner=await asyncio.to_thread(_grab,ips[0],port,payload)
        if banner:
            services[port]={"banner":banner[:200],"version":_parse_version(banner)}
            ctx.source(f"port-{port}")
    ctx.state["services"]=services
    ctx.state["service_count"]=len(services)
def _r_versions(s):
    svcs=s.get("services") or {}
    versioned=[(p,d["version"]) for p,d in svcs.items() if d.get("version")]
    if not versioned: return None
    return {"name":f"Service versions disclosed on {len(versioned)} port(s)","severity":"LOW","cwe":"CWE-200",
        "evidence":"; ".join(f":{p} = {v}" for p,v in versioned[:5]),
        "remediation":"Hide version banners. nginx: server_tokens off; Apache: ServerTokens Prod"}
def _r_count(s):
    n=s.get("service_count",0)
    if n==0: return None
    return {"name":f"{n} service banner(s) grabbed","severity":"INFO",
        "evidence":f"Ports: {list((s.get('services') or {}).keys())}"}
def _r_chain_handoff(s):
    svcs = s.get("services") or {}
    if not svcs:
        return None
    chain_next = []
    reasons = []
    HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888}
    DB_PORTS = {3306, 5432, 1433, 1521, 27017, 6379, 11211}
    MAIL_PORTS = {25, 110, 143, 465, 587, 993, 995}
    APPSERVER_HINTS = ("tomcat", "jetty", "weblogic", "jboss", "wildfly", "glassfish")
    VPN_HINTS = ("fortinet", "fortigate", "pulse", "citrix", "netscaler", "ivanti")
    NETDEV_HINTS = ("cisco", "juniper", "ios-xe", "ios-xr", "junos", "huawei", "mikrotik")
    for port, d in svcs.items():
        banner = (d.get("banner") or "")
        banner_l = banner.lower()
        version = d.get("version") or ""
        try:
            p_int = int(port)
        except Exception:
            p_int = 0
        if p_int in HTTP_PORTS or "http" in banner_l or "server:" in banner_l:
            if "http_server_cve" not in chain_next:
                chain_next.append("http_server_cve")
                reasons.append(f":{port} HTTP server -> http_server_cve")
        if p_int in DB_PORTS or any(x in banner_l for x in ("mysql", "postgres", "redis", "mongodb", "memcached")):
            if "database_server_cve" not in chain_next:
                chain_next.append("database_server_cve")
                reasons.append(f":{port} DB banner -> database_server_cve")
            if ("mysql" in banner_l or p_int == 3306) and "mysql_brute" not in chain_next:
                chain_next.append("mysql_brute")
                reasons.append(f":{port} MySQL -> mysql_brute")
            if (("postgres" in banner_l) or p_int == 5432) and "postgres_brute" not in chain_next:
                chain_next.append("postgres_brute")
                reasons.append(f":{port} Postgres -> postgres_brute")
        if p_int in MAIL_PORTS or any(x in banner_l for x in ("smtp", "imap", "pop3", "postfix", "exim", "sendmail")):
            if "mail_server_cve" not in chain_next:
                chain_next.append("mail_server_cve")
                reasons.append(f":{port} mail server -> mail_server_cve")
        if any(x in banner_l for x in APPSERVER_HINTS):
            if "appserver_cve" not in chain_next:
                chain_next.append("appserver_cve")
                reasons.append(f":{port} app server -> appserver_cve")
        if any(x in banner_l for x in VPN_HINTS):
            if "vpn_appliance_cve" not in chain_next:
                chain_next.append("vpn_appliance_cve")
                reasons.append(f":{port} VPN appliance -> vpn_appliance_cve")
        if any(x in banner_l for x in NETDEV_HINTS):
            if "network_device_cve" not in chain_next:
                chain_next.append("network_device_cve")
                reasons.append(f":{port} network device -> network_device_cve")
        if "ssh" in banner_l or p_int == 22:
            if "hydra_ssh_spray" not in chain_next:
                chain_next.append("hydra_ssh_spray")
                reasons.append(f":{port} SSH banner -> hydra_ssh_spray")
        if "smb" in banner_l or p_int in (139, 445):
            if "medusa_smb_spray" not in chain_next:
                chain_next.append("medusa_smb_spray")
                reasons.append(f":{port} SMB -> medusa_smb_spray")
        _ = version
    if not chain_next:
        return None
    return {
        "name": "Cross-module chain handoff - service versions identified",
        "severity": "INFO",
        "evidence": f"{len(chain_next)} services have follow-up scanners: " + "; ".join(reasons[:8]),
        "remediation": "Run the suggested CVE-lookup scanners against each identified version to find applicable CVEs + EPSS scores.",
        "cwe": "CWE-1006",
        "chain_next": chain_next,
        "discovery_method": "service_version_to_cve_chain",
        "source_stage": "chain_handoff",
        "confidence": "INFO",
    }
FINDING_RULES=[_r_versions,_r_count,_r_chain_handoff]
INTEL_FIELDS=[("Target IP","ip"),("Services","services"),("Service count","service_count")]
@router.post("/api/recon/service_version_detect")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="service_version_detect",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["services","service_count"])
def register(app): app.include_router(router)


async def _chain_callable(target, options, jwt=None) -> dict:
    return {"tool": "service_version_detect", "target": target, "_skipped": True,
            "skipped_reason": "Use orchestrator for full chain execution", "findings": []}
from tools._methodology import chain_registry
chain_registry.register("service_version_detect", _chain_callable)
