"""Telnet cleartext service exposure. VL-FORGE Vuln tier1 - playbook §1 #7."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools.vuln._vuln_common import tcp_probe
from tools._vl_core.verify import vl_verify

router = APIRouter()


async def gather(ctx):
    host = str(ctx.host)
    op, data = await asyncio.to_thread(tcp_probe, host, 23, b"", 64, 5)
    ctx.state["tested"] = 1
    if op:
        ctx.source("tcp-23")
        ctx.state["telnet_open"] = True
        ctx.state["telnet_banner"] = data.decode("utf-8", "ignore").strip()[:80]


def _r_telnet(s):
    if not s.get("telnet_open"):
        return None
    return {"name": "Telnet service exposed (port 23, cleartext)", "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-319",
            "evidence": "TCP 23 reachable - credentials transmitted in plaintext",
            "remediation": "Disable Telnet; use SSH. Firewall port 23."}


def _r_clean(s):
    if (s.get("tested") or 0) < 1 or s.get("telnet_open"):
        return None
    return {"name": "Telnet not exposed", "severity": "POSITIVE", "evidence": "Port 23 closed or filtered."}


FINDING_RULES = [_r_telnet, _r_clean]
INTEL_FIELDS = [("Telnet banner", "telnet_banner")]


@router.post("/api/vuln/telnet_exposure")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="telnet_exposure",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
