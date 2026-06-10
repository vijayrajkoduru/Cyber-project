"""TLS/SSL weakness — deprecated protocols + weak ciphers (POODLE/FREAK/SWEET32 surface).
VL-FORGE Vuln tier1 - playbook §1 #8."""
import asyncio
import socket
import ssl
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner

router = APIRouter()

_VERS = [("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
         ("TLS 1.2", ssl.TLSVersion.TLSv1_2), ("TLS 1.3", ssl.TLSVersion.TLSv1_3)]
_WEAK = ("RC4", "3DES", "DES", "EXPORT", "NULL", "MD5")


def _try(host, ver, timeout=5):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    try:
        c.minimum_version = ver
        c.maximum_version = ver
    except Exception:
        return None
    try:
        with socket.create_connection((host, 443), timeout=timeout) as s:
            with c.wrap_socket(s, server_hostname=host) as ss:
                return ss.cipher()
    except Exception:
        return None


async def gather(ctx):
    host = str(ctx.host)
    res = await asyncio.gather(*[asyncio.to_thread(_try, host, v) for _, v in _VERS])
    sup, cipher = {}, None
    for (name, _), r in zip(_VERS, res):
        sup[name] = r is not None
        if r:
            cipher = r[0]
    if not any(sup.values()):
        ctx.state["tested"] = 0
        return
    ctx.source("tls-443")
    ctx.state["tested"] = 1
    ctx.state["protocols"] = sup
    ctx.state["cipher"] = cipher


def _r_old(s):
    sup = s.get("protocols") or {}
    old = [v for v in ("TLS 1.0", "TLS 1.1") if sup.get(v)]
    if not old:
        return None
    return {"name": f"Deprecated TLS protocol(s) enabled: {', '.join(old)}", "severity": "HIGH", "cvss": 7.4,
            "cwe": "CWE-326", "evidence": f"Handshake completed on {', '.join(old)} (BEAST/POODLE-TLS class)",
            "remediation": "Disable TLS 1.0/1.1. nginx: ssl_protocols TLSv1.2 TLSv1.3;"}


def _r_weak(s):
    c = (s.get("cipher") or "").upper()
    w = [x for x in _WEAK if x in c]
    if not w:
        return None
    return {"name": f"Weak TLS cipher negotiated: {s.get('cipher')}", "severity": "HIGH", "cvss": 7.5,
            "cwe": "CWE-327", "evidence": f"Weakness: {', '.join(w)} (SWEET32/FREAK class)",
            "remediation": "Restrict to AEAD (AES-GCM/ChaCha20). Disable RC4/3DES/DES/EXPORT."}


def _r_no_modern(s):
    if (s.get("tested") or 0) < 1:
        return None
    sup = s.get("protocols") or {}
    if sup.get("TLS 1.2") or sup.get("TLS 1.3"):
        return None
    return {"name": "No modern TLS (1.2/1.3) supported", "severity": "HIGH", "cvss": 7.0, "cwe": "CWE-326",
            "evidence": "Only legacy TLS accepted", "remediation": "Enable TLS 1.2 + 1.3."}


def _r_clean(s):
    if (s.get("tested") or 0) < 1:
        return None
    sup = s.get("protocols") or {}
    if any(sup.get(v) for v in ("TLS 1.0", "TLS 1.1")):
        return None
    if any(x in (s.get("cipher") or "").upper() for x in _WEAK):
        return None
    return {"name": "TLS configuration strong (1.2/1.3, AEAD cipher)", "severity": "POSITIVE",
            "evidence": f"Negotiated {s.get('cipher')}; no deprecated protocols."}


FINDING_RULES = [_r_old, _r_weak, _r_no_modern, _r_clean]
INTEL_FIELDS = [("TLS cipher", "cipher")]


@router.post("/api/vuln/tls_ssl_weakness")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="tls_ssl_weakness",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
