"""SMB / RDP / NetBIOS internet exposure (EternalBlue/BlueKeep surface). VL-FORGE Vuln tier1 - §1 #4/#5."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import port_open

router = APIRouter()
_PORTS = [("smb", 445), ("netbios", 139), ("rdp", 3389)]


async def gather(ctx):
    host = str(ctx.host)
    res = await asyncio.gather(*[asyncio.to_thread(port_open, host, p) for _, p in _PORTS])
    tested = 0
    for (name, port), op in zip(_PORTS, res):
        tested += 1
        if op:
            ctx.source(f"tcp-{port}")
            ctx.state[f"{name}_open"] = True
    ctx.state["tested"] = tested


def _r_smb(s):
    ports = [p for p, k in (("445", "smb_open"), ("139", "netbios_open")) if s.get(k)]
    if not ports:
        return None
    return {"name": f"SMB exposed to the internet (port {', '.join(ports)})", "severity": "HIGH", "cvss": 7.5,
            "cwe": "CWE-668", "evidence": f"TCP {', '.join(ports)} reachable — EternalBlue/SMBGhost/ZeroLogon surface",
            "remediation": "Never expose SMB to the internet. Firewall 139/445; VPN-only; disable SMBv1."}


def _r_rdp(s):
    if not s.get("rdp_open"):
        return None
    return {"name": "RDP exposed to the internet (port 3389)", "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-668",
            "evidence": "TCP 3389 reachable — BlueKeep (CVE-2019-0708) / brute-force surface",
            "remediation": "Put RDP behind VPN/RD Gateway; enable NLA; firewall 3389; MFA."}


def _r_clean(s):
    if (s.get("tested") or 0) < 1:
        return None
    if any(s.get(k) for k in ("smb_open", "netbios_open", "rdp_open")):
        return None
    return {"name": "No SMB/RDP/NetBIOS exposure", "severity": "POSITIVE",
            "evidence": "Ports 139/445/3389 closed or filtered."}


FINDING_RULES = [_r_smb, _r_rdp, _r_clean]
INTEL_FIELDS = [("Exposure ports probed", "tested")]


@router.post("/api/vuln/smb_rdp_exposure")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="smb_rdp_exposure",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
