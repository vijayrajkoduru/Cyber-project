"""DB service banner -> NVD CVE (MySQL version from handshake; others port-detect). VL-FORGE Vuln tier2 §2 #19."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools.vuln._cve_intel import tcp_banner, high_cves
from tools._vl_core.verify import vl_verify
router = APIRouter()
_MYSQL = re.compile(r"([3-9]\.[0-9][0-9.]*)")
async def gather(ctx):
    host = str(ctx.host); ports = []
    ok, data = await asyncio.to_thread(tcp_banner, host, 3306, b"", 4)
    ver = None
    if ok:
        ports.append("3306/mysql")
        m = _MYSQL.search(data)
        if m: ver = m.group(1)
    for p, name in [(5432,"postgresql"),(1433,"mssql"),(1521,"oracle"),(27017,"mongodb"),(6379,"redis")]:
        ok2, _ = await asyncio.to_thread(tcp_banner, host, p, b"", 3)
        if ok2: ports.append(f"{p}/{name}")
    ctx.source("tcp"); ctx.state["probed"] = 1; ctx.state["open_db_ports"] = ports
    if ver:
        ctx.state["version"] = f"MySQL {ver}"
        h = await asyncio.to_thread(high_cves, "MySQL", ver)
        if h: ctx.state["cve_top"] = [f"{c} ({s})" for c, s in h[:3]]; ctx.state["cve_count"] = len(h)
def _r_cve(s):
    if not s.get("cve_top"): return None
    # ZERO-FP: the version IS a real signal (extracted from the MySQL
    # handshake), but the CVE ids come from an NVD KEYWORD search on
    # "MySQL <version>" and are mapped by name, not by an affected-range
    # check ("any CVE mentioning MySQL" rather than "CVEs whose affected range
    # contains THIS version"). Without range confirmation this is
    # version-INFERRED -> LOW, not MEDIUM. (MySQL versions are also commonly
    # backported by distros, so the digits alone do not prove vulnerability.)
    return {"name": f"Database '{s.get('version')}' has candidate CVEs (version-inferred, not range-confirmed)", "severity": "LOW", "cwe": "CWE-1395",
            "evidence": f"NVD keyword candidates: {', '.join(s['cve_top'])}. Version read from the MySQL handshake but NOT range-confirmed - verify this exact version against each CVE's affected range (backports may already patch it).", "remediation": "Confirm the exact build; if it is inside an affected range, upgrade the database engine. Bind to localhost / firewall the port regardless."}
def _r_clean(s):
    if not s.get("probed") or s.get("cve_top"): return None
    return {"name": "No version-vulnerable database service detected", "severity": "POSITIVE",
            "evidence": f"DB ports reachable: {', '.join(s.get('open_db_ports') or []) or 'none'}; no CVE-mappable version banner."}
FINDING_RULES = [_r_cve, _r_clean]; INTEL_FIELDS = [("Open DB ports","open_db_ports"),("DB version","version")]
@router.post("/api/vuln/database_server_cve")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="database_server_cve", gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
