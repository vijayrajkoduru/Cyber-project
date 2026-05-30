"""LDAP anonymous bind. VL-FORGE Vuln tier1 - playbook §1 #13."""
import asyncio
import socket
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner

router = APIRouter()
_BIND = bytes([0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00])


def _probe(host, port, timeout=6):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except Exception:
        return {"open": False}
    out = {"open": True}
    try:
        s.settimeout(timeout)
        s.sendall(_BIND)
        resp = s.recv(64)
        i = resp.find(b"\x61")
        if i != -1:
            j = resp.find(b"\x0a\x01", i)
            if j != -1 and j + 2 < len(resp):
                out["anon"] = (resp[j + 2] == 0x00)
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass
    return out


async def gather(ctx):
    host = str(ctx.host)
    tested = 0
    for port in (389, 636):
        res = await asyncio.to_thread(_probe, host, port)
        tested += 1
        if res.get("open"):
            ctx.source(f"tcp-{port}")
            ctx.state[f"ldap_{port}_open"] = True
            if res.get("anon"):
                ctx.state["ldap_anon"] = True
                ctx.state["ldap_port"] = port
    ctx.state["tested"] = tested


def _r_anon(s):
    if not s.get("ldap_anon"):
        return None
    return {"name": f"Anonymous LDAP bind allowed (port {s.get('ldap_port')})", "severity": "HIGH", "cvss": 7.5,
            "cwe": "CWE-287", "evidence": "LDAPv3 anonymous simple bind returned resultCode 0 (success)",
            "remediation": "Disable anonymous bind; require authenticated bind; restrict 389/636."}


def _r_exposed(s):
    if (s.get("tested") or 0) < 1 or s.get("ldap_anon"):
        return None
    if not (s.get("ldap_389_open") or s.get("ldap_636_open")):
        return None
    return {"name": "LDAP service exposed", "severity": "MEDIUM", "cwe": "CWE-668",
            "evidence": "TCP 389/636 reachable", "remediation": "Restrict LDAP; verify anonymous bind disabled."}


def _r_clean(s):
    if (s.get("tested") or 0) < 1:
        return None
    if s.get("ldap_389_open") or s.get("ldap_636_open"):
        return None
    return {"name": "No exposed LDAP service", "severity": "POSITIVE", "evidence": "Ports 389/636 closed or filtered."}


FINDING_RULES = [_r_anon, _r_exposed, _r_clean]
INTEL_FIELDS = [("LDAP ports probed", "tested")]


@router.post("/api/vuln/ldap_anon_bind")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="ldap_anon_bind",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
