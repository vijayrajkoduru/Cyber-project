"""HackerTarget reverse-IP lookup — playbook §2 #28.

Free, no API key, rate-limited to 25 req/day per source IP. Returns all
domains hosted on the same IP. Useful for shared-hosting recon (find
sister domains) and pivot to the customer's other assets.

Real probe. Zero false positives — returns only what HackerTarget actually
has indexed.
"""
import asyncio
import socket
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 15


def _resolve(t: str) -> str:
    t = t.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in t: t = t.split("/", 1)[0]
    if ":" in t: t = t.split(":", 1)[0]
    try:
        socket.inet_aton(t); return t
    except OSError:
        try: return socket.gethostbyname(t)
        except socket.gaierror: return t


def _do_scan(req: ScanRequest) -> dict:
    target = (req.target or "").strip()
    ip = _resolve(target)

    r = safe_get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                  req=req, timeout=10)
    if r is None or r.status_code != 200:
        return standard_response(
            tool="hackertarget_reverseip", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"hackertarget unreachable / rate-limited (status={r.status_code if r else 'no-conn'})")

    body = (r.text or "").strip()
    if "API count exceeded" in body or "error" in body.lower()[:50]:
        return standard_response(
            tool="hackertarget_reverseip", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="hackertarget rate-limited (25/day free)")

    domains = sorted({d.strip().lower() for d in body.splitlines()
                       if d.strip() and "." in d})

    if not domains:
        return standard_response(
            tool="hackertarget_reverseip", target=req.target,
            findings=[wrap_finding(
                f"No sibling domains found on {ip}",
                severity="POSITIVE", cwe="CWE-200",
                remediation="Dedicated IP — no shared-hosting noise.",
                evidence_marker="hackertarget returned 0 domains (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="Dedicated IP — no siblings")

    findings = []
    if len(domains) > 50:
        findings.append(wrap_finding(
            f"Mass shared-hosting detected: {len(domains)} domains on {ip}",
            severity="INFO", cwe="CWE-200",
            remediation="Shared hosting is common but cohabitant-domain abuse "
                        "(e.g. one compromised → IP-block reputation tarnished) is a real risk. "
                        "Consider migrating to dedicated IP for production.",
            evidence_marker=f"{len(domains)} domains co-hosted (CONFIRMED via hackertarget)"))

    findings.append(wrap_finding(
        f"Reverse-IP: {len(domains)} domain(s) on {ip}",
        severity="POSITIVE" if len(domains) <= 5 else "INFO",
        cwe="CWE-200",
        remediation="Cross-reference siblings with your domain portfolio — may "
                    "reveal forgotten / acquired / typosquat assets you own. "
                    "Or attacker assets if you don't own them.",
        evidence_marker=" | ".join(domains[:25])
                          + (' ...' if len(domains) > 25 else '')))

    return standard_response(
        tool="hackertarget_reverseip", target=req.target, findings=findings,
        tests_performed=1, vulnerable=False,
        tests_summary=f"{len(domains)} sibling domain(s) on {ip}",
        raw_data={"ip": ip, "domains": domains})


@router.post("/api/osint/hackertarget_reverseip")
async def scan_hackertarget_reverseip(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="hackertarget_reverseip", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
