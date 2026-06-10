"""Print-service exposure (CUPS/IPP 631, raw 9100). VL-FORGE Vuln tier2 §2 #24."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools.vuln._vuln_common import http_get
from tools.vuln._cve_intel import tcp_banner
router = APIRouter()
async def gather(ctx):
    host = str(ctx.host)
    r = await asyncio.to_thread(http_get, f"http://{host}:631/")
    cups = bool(r) and ("cups" in (str(r.get("headers", {})) + (r.get("body","") or "")[:2000]).lower())
    ok9100, _ = await asyncio.to_thread(tcp_banner, host, 9100, b"", 3)
    ctx.source("tcp"); ctx.state["probed"] = 1; ctx.state["cups"] = cups; ctx.state["raw9100"] = ok9100
def _r_cups(s):
    if not s.get("cups"): return None
    return {"name": "CUPS / IPP print service exposed (port 631)", "severity": "MEDIUM", "cvss": 6.0, "cwe": "CWE-1395",
            "evidence": "CUPS web interface reachable on :631 - associated with CVE-2024-47176 RCE chain (cups-browsed).",
            "remediation": "Disable cups-browsed / restrict port 631 and 5353 to localhost; patch CUPS."}
def _r_raw(s):
    if not s.get("raw9100") or s.get("cups"): return None
    return {"name": "Raw printing port (9100/JetDirect) exposed", "severity": "LOW", "cwe": "CWE-200",
            "evidence": "TCP 9100 open - allows unauthenticated raw print jobs / PJL abuse.",
            "remediation": "Firewall port 9100 to trusted print servers only."}
def _r_clean(s):
    if not s.get("probed") or s.get("cups") or s.get("raw9100"): return None
    return {"name": "No print services exposed", "severity": "POSITIVE", "evidence": "No CUPS/IPP (631) or raw (9100) print port reachable."}
FINDING_RULES = [_r_cups, _r_raw, _r_clean]; INTEL_FIELDS = []
@router.post("/api/vuln/print_server_cve")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="print_server_cve", gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
