"""Anonymous FTP login + cleartext exposure. VL-FORGE Vuln tier1 - §1 #7."""
import asyncio
import socket
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner

router = APIRouter()


def _probe(host, timeout=6):
    try:
        s = socket.create_connection((host, 21), timeout=timeout)
    except Exception:
        return {"open": False}
    out = {"open": True}
    try:
        s.settimeout(timeout)
        out["banner"] = s.recv(256).decode("utf-8", "ignore").strip()[:120]
        s.sendall(b"USER anonymous\r\n")
        s.recv(128)
        s.sendall(b"PASS anonymous@example.com\r\n")
        r2 = s.recv(128).decode("utf-8", "ignore")
        out["anon"] = "230" in r2
    except Exception:
        pass
    finally:
        try:
            s.sendall(b"QUIT\r\n")
            s.close()
        except Exception:
            pass
    return out


async def gather(ctx):
    host = str(ctx.host)
    res = await asyncio.to_thread(_probe, host)
    if not res.get("open"):
        ctx.state["tested"] = 0
        return
    ctx.source("tcp-21")
    ctx.state["tested"] = 1
    ctx.state["ftp_banner"] = res.get("banner")
    ctx.state["ftp_anon"] = res.get("anon")


def _r_anon(s):
    if not s.get("ftp_anon"):
        return None
    return {"name": "Anonymous FTP login allowed (port 21)", "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-306",
            "evidence": f"USER anonymous accepted (230). Banner: {s.get('ftp_banner')}",
            "remediation": "Disable anonymous FTP; require auth; prefer SFTP/FTPS."}


def _r_exposed(s):
    if (s.get("tested") or 0) < 1 or s.get("ftp_anon"):
        return None
    return {"name": "FTP service exposed (port 21, cleartext)", "severity": "LOW", "cwe": "CWE-319",
            "evidence": f"Banner: {s.get('ftp_banner')}",
            "remediation": "Use SFTP/FTPS; restrict 21 to trusted hosts."}


FINDING_RULES = [_r_anon, _r_exposed]
INTEL_FIELDS = [("FTP banner", "ftp_banner")]


@router.post("/api/vuln/ftp_anon")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="ftp_anon",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
