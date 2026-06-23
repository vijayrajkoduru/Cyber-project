"""Print-service exposure (CUPS/IPP 631, raw 9100). VL-FORGE Vuln tier2 §2 #24."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools.vuln._vuln_common import http_get
from tools.vuln._cve_intel import tcp_banner
from tools._vl_core.verify import vl_verify
router = APIRouter()
async def gather(ctx):
    host = str(ctx.host)
    r = await asyncio.to_thread(http_get, f"http://{host}:631/")
    # ZERO-FP: require an explicit "cups" marker in the response (header or
    # body) before treating :631 as a CUPS interface. An HTTP 200 on :631
    # alone (or any unrelated service answering on that port) is NOT proof -
    # without the marker this is just an open port, not a confirmed CUPS
    # service, so the CUPS finding must not fire.
    blob = (str(r.get("headers", {})) + (r.get("body","") or "")[:2000]).lower() if r else ""
    cups = bool(r) and ("cups" in blob)
    ok9100, _ = await asyncio.to_thread(tcp_banner, host, 9100, b"", 3)
    ctx.source("tcp"); ctx.state["probed"] = 1; ctx.state["cups"] = cups; ctx.state["raw9100"] = ok9100
def _r_cups(s):
    # Fires only when the "cups" marker was confirmed in gather() (see above) -
    # so the EXPOSURE is proven. The associated CVE is version-inferred (we did
    # not read a CUPS version), so it is called out as reference, not as a
    # confirmed exploitable CVE; the graded MEDIUM reflects the proven
    # internet/network exposure of the print service, not the CVE.
    if not s.get("cups"): return None
    return {"name": "CUPS / IPP print service exposed (port 631)", "severity": "MEDIUM", "cvss": 6.0, "cwe": "CWE-1395",
            "evidence": "CUPS web interface confirmed reachable on :631 (CUPS marker present in response). CVE-2024-47176 (cups-browsed RCE chain) is version-inferred reference - verify the exact CUPS/cups-browsed version against its affected range.",
            "remediation": "Disable cups-browsed / restrict port 631 and 5353 to localhost; confirm the CUPS version and patch if in an affected range."}
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
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="print_server_cve", gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
