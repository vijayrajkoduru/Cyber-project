"""WebSocket cross-origin handshake (CSWSH) audit. VL-FORGE Vuln tier6 - §6 #86/#87."""
import asyncio
import base64
import os
import socket
import ssl
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools._vl_core.verify import vl_verify

router = APIRouter()
_PATHS = ["/ws", "/websocket", "/socket", "/cable", "/api/ws", "/socket.io/?EIO=4&transport=websocket"]


def _ws(host, path, timeout=6):
    try:
        s = socket.create_connection((host, 443), timeout=timeout)
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        s = c.wrap_socket(s, server_hostname=host)
    except Exception:
        return None
    key = base64.b64encode(os.urandom(16)).decode()
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
           f"Origin: https://evil.example.com\r\n\r\n")
    try:
        s.sendall(req.encode())
        s.settimeout(timeout)
        return s.recv(256).decode("utf-8", "ignore")
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


async def gather(ctx):
    host = str(ctx.host)
    res = await asyncio.gather(*[asyncio.to_thread(_ws, host, p) for p in _PATHS])
    ctx.source("http")
    ctx.state["tested"] = len(_PATHS)
    hijackable = [p for p, r in zip(_PATHS, res) if r and "101" in r.split("\r\n", 1)[0]]
    if hijackable:
        ctx.state["cswsh"] = hijackable


def _r_cswsh(s):
    h = s.get("cswsh") or []
    if not h:
        return None
    return {"name": f"WebSocket accepts cross-origin handshake (CSWSH) at {h[0]}", "severity": "MEDIUM", "cvss": 6.5,
            "cwe": "CWE-346", "evidence": f"101 Switching Protocols returned for Origin https://evil.example.com on {', '.join(h)}",
            "remediation": "Validate the Origin header on WS upgrade; require an auth token bound to the session post-upgrade."}


def _r_clean(s):
    if (s.get("tested") or 0) < 1 or s.get("cswsh"):
        return None
    return {"name": "No cross-origin WebSocket hijack", "severity": "POSITIVE",
            "evidence": "No WS endpoint accepted a forged-Origin upgrade."}


FINDING_RULES = [_r_cswsh, _r_clean]
INTEL_FIELDS = [("CSWSH endpoints", "cswsh")]


@router.post("/api/vuln/websocket_security")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="websocket_security",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
