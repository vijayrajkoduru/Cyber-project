"""NTP monlist amplification (CVE-2013-5211). VL-FORGE Vuln tier1 - playbook §1 #10."""
import asyncio
import socket
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner

router = APIRouter()
_MONLIST = b"\x17\x00\x03\x2a" + b"\x00" * 4


def _probe(host, timeout=4):
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(_MONLIST, (host, 123))
        data, _ = s.recvfrom(1024)
        return len(data) > 0
    except Exception:
        return False
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


async def gather(ctx):
    vuln = await asyncio.to_thread(_probe, str(ctx.host))
    ctx.state["tested"] = 1
    ctx.source("udp-123")
    ctx.state["ntp_monlist"] = vuln


def _r_monlist(s):
    if not s.get("ntp_monlist"):
        return None
    return {"name": "NTP monlist enabled (amplification DDoS)", "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-406",
            "evidence": "Mode-7 monlist request returned data (CVE-2013-5211)",
            "remediation": "Set 'disable monitor' in ntp.conf; upgrade to ntp 4.2.7+; restrict queries."}


def _r_clean(s):
    if (s.get("tested") or 0) < 1 or s.get("ntp_monlist"):
        return None
    return {"name": "NTP monlist amplification not exposed", "severity": "POSITIVE",
            "evidence": "No mode-7 monlist response."}


FINDING_RULES = [_r_monlist, _r_clean]
INTEL_FIELDS = [("NTP monlist", "ntp_monlist")]


@router.post("/api/vuln/ntp_monlist")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="ntp_monlist",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
