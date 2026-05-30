"""HTTP/2 cleartext (h2c) upgrade smuggling probe. VL-FORGE Vuln tier6 §6 #90."""
import asyncio, socket, ssl
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
router = APIRouter()
_REQ = ("GET / HTTP/1.1\r\nHost: {h}\r\nConnection: Upgrade, HTTP2-Settings\r\n"
        "Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA\r\n\r\n")
def _probe(host, port, tls):
    try:
        s = socket.create_connection((host, port), timeout=6)
        if tls:
            s = ssl._create_unverified_context().wrap_socket(s, server_hostname=host)
        s.settimeout(6)
        s.sendall(_REQ.format(h=host).encode())
        data = s.recv(512).decode("latin-1", "replace")
        s.close()
        return data
    except Exception:
        return ""
async def gather(ctx):
    host = str(ctx.host)
    r80 = await asyncio.to_thread(_probe, host, 80, False)
    r443 = await asyncio.to_thread(_probe, host, 443, True)
    ctx.source("tcp"); ctx.state["probed"] = 1
    accepted = []
    for port, resp in [(80, r80), (443, r443)]:
        first = (resp.splitlines() or [""])[0]
        if "101" in first and "switching protocols" in resp.lower() and "h2c" in resp.lower():
            accepted.append(port)
    ctx.state["h2c_ports"] = accepted
    ctx.state["status_lines"] = [x for x in [(r80.splitlines() or [""])[0], (r443.splitlines() or [""])[0]] if x]
def _r(s):
    a = s.get("h2c_ports") or []
    if not a: return None
    return {"name": f"Server accepts h2c upgrade on port(s) {a} - HTTP/2 cleartext smuggling surface", "severity": "MEDIUM", "cvss": 5.8, "cwe": "CWE-444",
            "evidence": f"101 Switching Protocols to 'Upgrade: h2c' on {a}. A front-end that blindly proxies h2c can be desynced (h2c smuggling).",
            "remediation": "Reject 'Upgrade: h2c' at the edge proxy; disable cleartext HTTP/2 upgrade on front-ends."}
def _r_clean(s):
    if not s.get("probed") or (s.get("h2c_ports") or []): return None
    return {"name": "No h2c upgrade accepted", "severity": "POSITIVE", "evidence": f"Server did not switch to h2c (status: {', '.join(s.get('status_lines') or []) or 'no response'})."}
FINDING_RULES = [_r, _r_clean]; INTEL_FIELDS = []
@router.post("/api/vuln/h2c_smuggling")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="h2c_smuggling", gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
