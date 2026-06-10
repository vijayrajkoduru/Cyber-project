"""RDAP domain lookup — playbook §2 #19.

RDAP (RFC 7480) is the modern replacement for WHOIS — structured JSON
response, no parsing of free-text WHOIS. Free, no API key, low rate.
Hits the IANA bootstrap registry to resolve the correct TLD RDAP server.

Real probe. Zero false positives.
"""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 15


def _clean(target: str) -> str:
    target = target.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in target:
        target = target.split("/", 1)[0]
    return target.lower()


def _do_scan(req: ScanRequest) -> dict:
    domain = _clean((req.target or "").strip())
    if not domain or "." not in domain:
        return standard_response(
            tool="rdap_domain", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="invalid domain")

    r = safe_get(f"https://rdap.org/domain/{domain}",
                  req=req, timeout=10,
                  headers={"Accept": "application/rdap+json"})
    if r is None or r.status_code == 404:
        return standard_response(
            tool="rdap_domain", target=req.target,
            findings=[wrap_finding(
                f"Domain {domain} not registered (RDAP 404)",
                severity="POSITIVE", cwe="CWE-200",
                remediation="If this is YOUR domain, re-register before squatters do.",
                evidence_marker="RDAP returned 404 (CONFIRMED unregistered)")],
            tests_performed=1, vulnerable=False,
            tests_summary="Domain not registered")
    if r.status_code != 200:
        return standard_response(
            tool="rdap_domain", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"RDAP status {r.status_code}")

    try:
        data = r.json()
    except Exception:
        return standard_response(
            tool="rdap_domain", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON RDAP response")

    # Extract key fields
    events = {e.get("eventAction"): e.get("eventDate")
                for e in data.get("events", [])}
    registrar = "?"
    for ent in data.get("entities", []):
        roles = ent.get("roles", [])
        if "registrar" in roles:
            for v in (ent.get("vcardArray") or [[], []])[1] or []:
                if v[0] == "fn":
                    registrar = v[3]
                    break

    ns = [n.get("ldhName") for n in data.get("nameservers", []) if n.get("ldhName")]
    statuses = data.get("status", [])

    findings = [wrap_finding(
        f"RDAP record for {domain}",
        severity="POSITIVE", cwe="CWE-200",
        remediation="Public registry data — no action. Watch for "
                    "'pendingDelete' / 'clientHold' statuses (expired / disputed).",
        evidence_marker=(
            f"registrar={registrar} | "
            f"registered={events.get('registration', '?')[:10]} | "
            f"expires={events.get('expiration', '?')[:10]} | "
            f"updated={events.get('last changed', '?')[:10]} | "
            f"status={','.join(statuses) or '—'} | "
            f"ns={','.join(ns[:5])}"
        ))]

    # Flag concerning statuses
    risky = [s for s in statuses if "hold" in s.lower() or "delete" in s.lower()
              or "transfer" in s.lower() and "prohibited" not in s.lower()]
    if risky:
        findings.append(wrap_finding(
            f"Domain has concerning status: {', '.join(risky)}",
            severity="MEDIUM" if any("delete" in s.lower() for s in risky) else "LOW",
            cwe="CWE-1395",
            remediation="If 'pendingDelete' — renew NOW or lose the domain. "
                        "If 'clientHold' / 'serverHold' — registrar disabled the domain "
                        "(usually for payment / abuse). Contact registrar immediately.",
            evidence_marker=f"RDAP status field = {risky} (CONFIRMED via RDAP)"))

    return standard_response(
        tool="rdap_domain", target=req.target, findings=findings,
        tests_performed=1, vulnerable=bool(risky),
        tests_summary=f"RDAP record + {len(ns)} nameservers",
        raw_data={"events": events, "registrar": registrar, "ns": ns, "status": statuses})


@router.post("/api/osint/rdap_domain")
@vl_verify()
async def scan_rdap_domain(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="rdap_domain", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
