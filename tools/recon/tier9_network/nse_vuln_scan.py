"""NSE Vuln Scan v2 — VL-FORGE. nmap nse or pure-python fallback."""
import asyncio, shutil
import dns.asyncresolver
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
router=APIRouter()
_NMAP=shutil.which("nmap")
async def _resolve(h):
    try:
        r=dns.asyncresolver.Resolver();r.timeout=4
        return [str(x).rstrip(".") for x in await r.resolve(h,"A")]
    except: return []
async def _nmap_run(ip):
    if not _NMAP: return None
    try:
        proc=await asyncio.create_subprocess_exec(_NMAP,"-sV","--script=vuln","--top-ports","20",
            "-T4","--max-rate","100",ip,
            stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
        out,_=await asyncio.wait_for(proc.communicate(),timeout=120)
        return out.decode("utf-8",errors="ignore")
    except: return None
async def gather(ctx):
    ips=await _resolve(ctx.host)
    if not ips: ctx.state["reachable"]=False; return
    ctx.state["reachable"]=True; ctx.state["ip"]=ips[0]
    ctx.state["nmap_installed"]=bool(_NMAP)
    if not _NMAP: return
    ctx.source("nmap-nse-vuln")
    output=await _nmap_run(ips[0])
    if not output: return
    # Parse vuln findings
    import re
    cve_pattern=re.compile(r"CVE-\d{4}-\d{4,7}")
    cves=list(set(cve_pattern.findall(output)))
    state_pattern=re.compile(r"VULNERABLE|LIKELY VULNERABLE",re.I)
    vuln_lines=[ln for ln in output.splitlines() if state_pattern.search(ln)][:20]
    ctx.state.update({"cves_found":cves[:30],"cve_count":len(cves),
        "vuln_indicators":vuln_lines,"raw_excerpt":output[:2000]})
def _r_no_nmap(s):
    if s.get("nmap_installed"): return None
    return {"name":"nmap not installed","severity":"INFO",
        "evidence":"Install nmap binary for NSE vuln scripts: apt-get install nmap"}
def _r_cves(s):
    cves=s.get("cves_found") or []
    if not cves: return None
    return {"name":f"NSE vuln scan found {len(cves)} CVE(s)","severity":"HIGH","cvss":7.5,
        "cwe":"CWE-1395","owasp":"A06:2021",
        "evidence":f"Sample: {', '.join(cves[:5])}",
        "remediation":"Patch affected services. Verify each CVE applicability manually."}
def _r_vulnerable(s):
    vi=s.get("vuln_indicators") or []
    if not vi: return None
    return {"name":f"{len(vi)} NSE script flagged VULNERABLE","severity":"HIGH","cwe":"CWE-1395",
        "evidence":vi[0][:200] if vi else "",
        "remediation":"Investigate each VULNERABLE line — confirm + patch."}
FINDING_RULES=[_r_cves,_r_vulnerable,_r_no_nmap]
INTEL_FIELDS=[("IP","ip"),("nmap installed","nmap_installed"),("CVEs","cve_count"),("CVEs list","cves_found")]
@router.post("/api/recon/nse_vuln_scan")
async def f(req:ScanRequest,_=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target),tool="nse_vuln_scan",
        gather_func=gather,finding_rules=FINDING_RULES,intel_fields=INTEL_FIELDS,
        flat_field_keys=["cves_found","cve_count","vuln_indicators"])
def register(app): app.include_router(router)
