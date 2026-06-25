"""SSLMate CertSpotter cert-history lookup — playbook §2 #23 (alt source).

CertSpotter (api.certspotter.com) is a free CT-log monitor with a public
JSON API: returns all certificates issued for a domain, with issuer +
not-before/not-after. Complements crt.sh — different ingestion pipeline,
different latency, occasionally finds certs the other source missed.

Real probe. Zero false positives. Free, no key (rate-limited 100 req/hr).
"""
import asyncio
from datetime import datetime, UTC
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 18


def _clean(t: str) -> str:
    t = t.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in t: t = t.split("/", 1)[0]
    return t.lower()


def _do_scan(req: ScanRequest) -> dict:
    domain = _clean((req.target or "").strip())
    if not domain or "." not in domain:
        return standard_response(
            tool="certspotter_history", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="invalid domain")

    r = safe_get(
        f"https://api.certspotter.com/v1/issuances?domain={domain}"
        "&include_subdomains=true&expand=dns_names&expand=issuer",
        req=req, timeout=15,
        headers={"User-Agent": "VulnusLab-OSINT/1.0"})
    if r is None or r.status_code != 200:
        return standard_response(
            tool="certspotter_history", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"CertSpotter status {r.status_code if r else 'no-conn'}")

    try:
        certs = r.json()
    except Exception:
        return standard_response(
            tool="certspotter_history", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON CertSpotter response")

    if not certs:
        return standard_response(
            tool="certspotter_history", target=req.target,
            findings=[wrap_finding(
                f"CertSpotter: 0 issuances for {domain}",
                severity="POSITIVE", cwe="CWE-200",
                remediation="No CT records — domain hasn't had a public cert "
                            "(or CertSpotter's free tier misses some — try crtsh_full_certs).",
                evidence_marker="CertSpotter returned [] (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="No CertSpotter records")

    subs = set()
    issuers = set()
    now = datetime.now(UTC).timestamp()
    expired = 0
    active = 0

    for c in certs:
        for n in (c.get("dns_names") or []):
            n = n.lower().lstrip("*.")
            if n.endswith(domain): subs.add(n)
        if c.get("issuer"):
            issuers.add(c["issuer"].get("name", "?"))
        # Parse not_after
        na = c.get("not_after", "")
        try:
            dt = datetime.fromisoformat(na.replace("Z", "+00:00"))
            if dt.timestamp() < now: expired += 1
            else: active += 1
        except Exception:
            pass

    subs = sorted(subs)
    # CT-logged subdomains are PUBLIC inventory, not an exposure — api.<domain>
    # is normally an intended public service. Only subdomains that look like
    # internal/pre-prod tooling (which usually should NOT be public) warrant a
    # LOW; generic api/dev/test/admin names are INFO attack-surface inventory.
    _INTERNAL = ("internal", "vpn", "jenkins", "jira", "staging", "uat", "qa")
    _GENERIC = ("dev", "test", "admin", "api", "git")
    internalish = [s for s in subs if any(k in s for k in _INTERNAL)]
    generic = [s for s in subs if any(k in s for k in _GENERIC) and s not in internalish]
    interesting = internalish + generic

    findings = []
    if internalish:
        findings.append(wrap_finding(
            f"Internal/pre-prod-looking subdomains in CT logs ({len(internalish)})",
            severity="LOW", cvss="3.1", cwe="CWE-200", owasp="A05:2021",
            remediation="These CT-logged subdomains look like internal/pre-prod systems "
                        "(internal/vpn/jenkins/jira/staging/uat). CT is public, so issuing a "
                        "cert advertises their existence. Confirm which are meant to be public; "
                        "put the rest behind a VPN or use a wildcard / private CA.",
            evidence_marker=" | ".join(internalish[:15])))
    if generic:
        findings.append(wrap_finding(
            f"Subdomain inventory from CT logs ({len(generic)} api/dev/admin-style)",
            severity="INFO", cvss="0.0", cwe="CWE-200", owasp="A05:2021",
            remediation="CT-logged subdomains (api/dev/test/admin/git) — attack-surface "
                        "inventory, not an exposure (e.g. api.<domain> is normally public). "
                        "Use as a recon target list.",
            evidence_marker=" | ".join(generic[:15])))

    findings.append(wrap_finding(
        f"CertSpotter: {len(certs)} issuances / {len(subs)} unique subs for {domain}",
        severity="POSITIVE" if not interesting else "INFO", cwe="CWE-200",
        remediation="Cross-reference with crtsh_full_certs — same source (CT logs) "
                    "but independent ingestion may surface different records.",
        evidence_marker=(
            f"active_certs={active} | expired={expired} | "
            f"issuers={', '.join(sorted(issuers)[:5])} | "
            f"sample_subs: {', '.join(subs[:10])}"
        )))

    return standard_response(
        tool="certspotter_history", target=req.target, findings=findings,
        tests_performed=1, vulnerable=bool(internalish),
        tests_summary=f"CertSpotter: {len(certs)} certs / {len(subs)} subs",
        raw_data={"subdomains": subs, "interesting": interesting,
                   "issuers": sorted(issuers), "active": active, "expired": expired})


@router.post("/api/osint/certspotter_history")
@vl_verify()
async def scan_certspotter_history(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="certspotter_history", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
