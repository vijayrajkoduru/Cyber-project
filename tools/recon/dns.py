"""DNS recon — public DNS posture intelligence.

Active verification via dnspython. Confirmed findings on:
  - SPF record (email spoofing protection)
  - DMARC policy
  - MX records
  - CAA records (certificate authority restrictions)
  - Wildcard DNS (subdomain takeover surface)
  - Open zone transfer (AXFR)
"""
import uuid
import dns.resolver
import dns.query
import dns.zone
import dns.exception
from fastapi import APIRouter, Depends

from tools._shared import (
    ScanRequest, verify_scan_quota, recon_host,
    wrap_finding, standard_response,
)

router = APIRouter()


def _query(domain, rtype):
    """Resolve a record type. Returns list of stringified records, or []."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 8
        resolver.timeout = 4
        ans = resolver.resolve(domain, rtype)
        return [r.to_text() for r in ans]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


@router.post("/api/scan/dns")
async def scan_dns(req: ScanRequest, _=Depends(verify_scan_quota)):
    target = recon_host(req.target)
    findings = []
    tests = 0
    raw = {}

    # Sanity gate — does the domain resolve at all?
    a_records = _query(target, "A")
    if not a_records:
        return standard_response(
            tool="dns", target=target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Domain {target} does not resolve (no A records)",
        )
    raw["a_records"] = a_records

    # Test 1 — SPF (lives in TXT records at apex)
    tests += 1
    txt = _query(target, "TXT")
    raw["txt_records"] = txt
    spf = next((t for t in txt if "v=spf1" in t.lower()), None)
    raw["spf"] = spf
    if not spf:
        findings.append(wrap_finding(
            "No SPF record found — email spoofing prevention missing",
            "HIGH", cwe="CWE-290", owasp="A07:2021",
            evidence_marker=f"TXT records present: {len(txt)}, none contain v=spf1",
            remediation="Publish a TXT record like 'v=spf1 mx -all' at the apex domain.",
            tests_performed=1,
        ))
    elif "-all" not in spf and "~all" not in spf:
        findings.append(wrap_finding(
            "SPF record uses neutral/no policy (no -all or ~all)",
            "MEDIUM", cwe="CWE-290",
            evidence_marker=f"spf={spf[:120]}",
            remediation="Tighten SPF to '-all' (hard fail) or '~all' (soft fail).",
            tests_performed=1,
        ))

    # Test 2 — DMARC
    tests += 1
    dmarc_recs = _query(f"_dmarc.{target}", "TXT")
    dmarc = next((t for t in dmarc_recs if "v=dmarc1" in t.lower()), None)
    raw["dmarc"] = dmarc
    if not dmarc:
        findings.append(wrap_finding(
            "No DMARC record found — no email authentication policy published",
            "HIGH", cwe="CWE-290", owasp="A07:2021",
            evidence_marker=f"_dmarc.{target} has no v=DMARC1 TXT",
            remediation="Publish a DMARC TXT at _dmarc.<domain>, e.g. 'v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>'",
            tests_performed=1,
        ))
    elif "p=none" in dmarc.lower():
        findings.append(wrap_finding(
            "DMARC policy is p=none (monitoring only, no enforcement)",
            "MEDIUM", cwe="CWE-290",
            evidence_marker=f"dmarc={dmarc[:140]}",
            remediation="Tighten policy to p=quarantine or p=reject once mail flow is verified.",
            tests_performed=1,
        ))

    # Test 3 — MX records
    tests += 1
    mx = _query(target, "MX")
    raw["mx"] = mx
    if not mx:
        findings.append(wrap_finding(
            "No MX records — domain cannot receive email",
            "INFO",
            evidence_marker="MX query returned 0 records",
            tests_performed=1,
        ))

    # Test 4 — CAA records
    tests += 1
    caa = _query(target, "CAA")
    raw["caa"] = caa
    if not caa:
        findings.append(wrap_finding(
            "No CAA records — any certificate authority may issue TLS certs for this domain",
            "MEDIUM", cwe="CWE-295", owasp="A02:2021",
            evidence_marker="CAA query returned 0 records",
            remediation="Add CAA records restricting which CAs may issue certs, e.g. '0 issue \"letsencrypt.org\"'.",
            tests_performed=1,
        ))

    # Test 5 — Wildcard DNS probe
    tests += 1
    random_sub = f"{uuid.uuid4().hex[:12]}.{target}"
    wildcard_resp = _query(random_sub, "A")
    raw["wildcard_probe"] = {"name": random_sub, "resolved": wildcard_resp}
    if wildcard_resp:
        findings.append(wrap_finding(
            f"Wildcard DNS detected — random subdomain '{random_sub}' resolves to {wildcard_resp[0]}",
            "MEDIUM", cwe="CWE-264",
            evidence_marker=f"random_sub={random_sub} resolved={wildcard_resp[0]}",
            remediation="Remove wildcard A/AAAA records or scope them tightly; they enable subdomain takeover paths.",
            tests_performed=1,
        ))

    # Test 6 — Open zone transfer (AXFR) on each NS
    tests += 1
    ns_records = _query(target, "NS")
    raw["ns"] = ns_records
    axfr_open = []
    for ns_rec in ns_records:
        ns_host = ns_rec.rstrip(".").rstrip(",")
        try:
            xfr = dns.zone.from_xfr(dns.query.xfr(ns_host, target, lifetime=5))
            if xfr:
                names = [str(n) for n in list(xfr.nodes.keys())[:5]]
                axfr_open.append({"ns": ns_host, "sample_nodes": names})
        except Exception:
            pass
    raw["axfr_open"] = axfr_open
    if axfr_open:
        ns_list = ", ".join(a["ns"] for a in axfr_open)
        findings.append(wrap_finding(
            f"Open zone transfer (AXFR) on: {ns_list} — full DNS zone leaked",
            "HIGH", cwe="CWE-200", owasp="A01:2021",
            evidence_marker=f"AXFR succeeded on {len(axfr_open)} NS",
            remediation="Restrict AXFR to authorized secondaries only via TSIG or NS ACLs.",
            tests_performed=max(1, len(ns_records)),
        ))

    return standard_response(
        tool="dns", target=target, findings=findings,
        tests_performed=tests,
        tests_summary="6 DNS checks: SPF, DMARC, MX, CAA, wildcard, AXFR",
        raw_data={"dns": raw},
    )


def register(app):
    app.include_router(router)
