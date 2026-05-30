"""Censys certificate search — playbook §2 #25 / §4.

Censys has a free tier (250 queries/month) for cert+host search. Without
an API key, falls back to advisory + how-to (Censys requires auth even
for low volume). With auth_bearer set as "API_ID:API_SECRET", does a
real cert search by domain.

Real probe when key is set. Zero false positives.
"""
import asyncio
import base64
import urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 12


def _clean(t: str) -> str:
    t = t.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in t: t = t.split("/", 1)[0]
    return t.lower()


def _do_scan(req: ScanRequest) -> dict:
    domain = _clean((req.target or "").strip())
    if not domain or "." not in domain:
        return standard_response(
            tool="censys_certs_free", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="invalid domain")

    api_creds = (req.auth_bearer or "").strip()
    if ":" not in api_creds:
        return standard_response(
            tool="censys_certs_free", target=req.target,
            findings=[wrap_finding(
                "Censys cert search requires API_ID:API_SECRET via auth_bearer",
                severity="INFO", cwe="CWE-1395",
                remediation=(
                    "Sign up free at https://search.censys.io (250 free queries/mo). "
                    "Pass auth_bearer as 'API_ID:API_SECRET'. Until then, use crt.sh "
                    "(no key — already in tier6 as crtsh_full_certs) — Censys adds "
                    "host+cert correlation but crt.sh covers raw CT enumeration."
                ),
                evidence_marker=f"domain={domain} | no Censys API creds configured")],
            tests_performed=0, vulnerable=False,
            tests_summary="Censys API creds not configured")

    auth = base64.b64encode(api_creds.encode()).decode()
    q = urllib.parse.quote(f"names: {domain}")
    r = safe_get(
        f"https://search.censys.io/api/v2/certificates/search?q={q}&per_page=25",
        req=req, timeout=10,
        headers={"Authorization": f"Basic {auth}",
                  "User-Agent": "VulnusLab-OSINT/1.0"})
    if r is None:
        return standard_response(
            tool="censys_certs_free", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="Censys unreachable")
    if r.status_code == 401:
        return standard_response(
            tool="censys_certs_free", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="Censys 401 — bad API_ID:API_SECRET")
    if r.status_code != 200:
        return standard_response(
            tool="censys_certs_free", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Censys status {r.status_code} (free-tier exhausted?)")

    try:
        data = r.json()
    except Exception:
        return standard_response(
            tool="censys_certs_free", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON Censys response")

    hits = data.get("result", {}).get("hits", [])
    if not hits:
        return standard_response(
            tool="censys_certs_free", target=req.target,
            findings=[wrap_finding(
                f"Censys: 0 certificates indexed for {domain}",
                severity="POSITIVE", cwe="CWE-200",
                remediation="No certs in Censys index.",
                evidence_marker="Censys returned 0 hits (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="No Censys certs")

    # Extract unique subdomain names across all certs
    subs = set()
    for h in hits:
        for n in (h.get("names") or []):
            if n.endswith(domain) and not n.startswith("*"):
                subs.add(n.lower())

    return standard_response(
        tool="censys_certs_free", target=req.target,
        findings=[wrap_finding(
            f"Censys — {len(hits)} cert(s) / {len(subs)} unique subdomain(s) for {domain}",
            severity="POSITIVE", cwe="CWE-200",
            remediation="Cross-reference subdomains with crtsh_full_certs + Amass. "
                        "Censys adds host correlation (which IPs serve which cert) "
                        "that crt.sh alone doesn't provide.",
            evidence_marker=f"sample: {', '.join(sorted(subs)[:15])} "
                              f"(CONFIRMED via Censys cert search)")],
        tests_performed=1, vulnerable=False,
        tests_summary=f"Censys: {len(hits)} certs / {len(subs)} subs",
        raw_data={"hit_count": len(hits), "unique_subdomains": sorted(subs)})


@router.post("/api/osint/censys_certs_free")
async def scan_censys_certs_free(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="censys_certs_free", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
