"""SNMP default 'public' community readable. VL-FORGE Vuln tier1 - playbook §1 #7."""
import asyncio
import socket
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools._vl_core.verify import vl_verify

router = APIRouter()
_GET = bytes.fromhex("302902010104067075626c6963a01c020412345678020100020100300e300c06082b060102010101000500")


def _probe(host, timeout=4):
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(_GET, (host, 161))
        data, _ = s.recvfrom(2048)
        return data
    except Exception:
        return b""
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


async def gather(ctx):
    host = str(ctx.host)
    data = await asyncio.to_thread(_probe, host)
    ctx.state["tested"] = 1
    ctx.source("udp-161")
    if data:
        ctx.state["snmp_public"] = True
        txt = "".join(chr(b) if 32 <= b < 127 else " " for b in data).strip()
        ctx.state["snmp_sysdescr"] = txt[-100:]


def _r_public(s):
    if not s.get("snmp_public"):
        return None
    return {"name": "SNMP 'public' community readable (port 161)", "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-200",
            "evidence": f"sysDescr via community 'public': {s.get('snmp_sysdescr') or '(response received)'}",
            "remediation": "Change default community; use SNMPv3 with auth+priv; firewall UDP 161."}


def _r_clean(s):
    if (s.get("tested") or 0) < 1 or s.get("snmp_public"):
        return None
    return {"name": "SNMP 'public' community not readable", "severity": "POSITIVE",
            "evidence": "No SNMPv2c response to default community."}


FINDING_RULES = [_r_public, _r_clean]
INTEL_FIELDS = [("SNMP sysDescr", "snmp_sysdescr")]


@router.post("/api/vuln/snmp_public_community")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="snmp_public_community",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
