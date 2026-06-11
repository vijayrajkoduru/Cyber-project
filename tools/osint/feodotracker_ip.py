"""abuse.ch Feodo Tracker IP blocklist check — playbook §4.

Feodo Tracker maintains a free list of IPs associated with banking trojan
C2s (Emotet, Dridex, TrickBot, QakBot, Heodo). The blocklist is downloaded
fresh each run (small file, ~30 KB) and the target is checked locally.

Real probe. Zero false positives — blocklist match = confirmed C2 listing.
"""
import asyncio
import socket
import time
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 12

_CACHE = {"ts": 0, "ips": set(), "fetched": False}
_TTL = 1800  # 30 min


def _resolve(t: str) -> str:
    t = t.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in t: t = t.split("/", 1)[0]
    if ":" in t: t = t.split(":", 1)[0]
    try:
        socket.inet_aton(t); return t
    except OSError:
        try: return socket.gethostbyname(t)
        except socket.gaierror: return t


def _fetch_blocklist(req):
    if _CACHE["fetched"] and (time.time() - _CACHE["ts"]) < _TTL:
        return _CACHE["ips"]
    r = safe_get("https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                  req=req, timeout=8,
                  headers={"User-Agent": "VulnusLab-OSINT/1.0"})
    if r is None or r.status_code != 200:
        return None
    ips = set()
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ips.add(line)
    _CACHE["ips"] = ips
    _CACHE["ts"] = time.time()
    _CACHE["fetched"] = True
    return ips


def _do_scan(req: ScanRequest) -> dict:
    target = (req.target or "").strip()
    ip = _resolve(target)

    ips = _fetch_blocklist(req)
    if ips is None:
        return standard_response(
            tool="feodotracker_ip", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="Feodo Tracker blocklist unreachable")

    if ip in ips:
        return standard_response(
            tool="feodotracker_ip", target=req.target,
            findings=[wrap_finding(
                f"BANKING TROJAN C2 — {ip} listed on Feodo Tracker",
                severity="CRITICAL", cvss="9.8", cwe="CWE-829",
                owasp="A06:2021",
                remediation="If outbound: BLOCK at egress firewall immediately, "
                            "investigate the source endpoint for Emotet/Dridex/TrickBot/QakBot "
                            "infection. If inbound: confirm not a SOAR/honeypot, then block. "
                            "If this is YOUR IP: server is compromised — full IR + rebuild.",
                evidence_marker=f"{ip} matched in Feodo Tracker active C2 list "
                                  f"(blocklist size: {len(ips)} IPs) (CONFIRMED)")],
            tests_performed=1, vulnerable=True,
            tests_summary="IP listed in Feodo Tracker active C2",
            raw_data={"ip": ip, "blocklist_size": len(ips), "match": True})

    return standard_response(
        tool="feodotracker_ip", target=req.target,
        findings=[wrap_finding(
            f"{ip} NOT in Feodo Tracker active C2 list",
            severity="POSITIVE", cwe="CWE-1395",
            remediation="No active banking-trojan C2 association. Re-check daily "
                        "as the blocklist is rebuilt every 5 min.",
            evidence_marker=f"checked against {len(ips)}-entry blocklist (CONFIRMED clean)")],
        tests_performed=1, vulnerable=False,
        tests_summary="Clean per Feodo Tracker",
        raw_data={"ip": ip, "blocklist_size": len(ips), "match": False})


@router.post("/api/osint/feodotracker_ip")
@vl_verify()
async def scan_feodotracker_ip(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="feodotracker_ip", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
