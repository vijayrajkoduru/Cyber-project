"""saml_response_time_bomb — SAML metadata clock-skew + validity audit.

Discover SAML SP metadata (/Shibboleth.sso/Metadata or auto-discovered)
and audit the AssertionConsumerService settings + signing-cert validity
window. Long-validity signing certs + lax NotOnOrAfter tolerance =
'time-bomb' for replay attacks.
"""
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

META_PATHS = [
    "/Shibboleth.sso/Metadata",
    "/saml/metadata", "/saml2/metadata", "/sp/metadata",
    "/auth/saml/metadata", "/auth/saml2/metadata",
    "/.well-known/saml-configuration",
]


@router.post("/api/webapp/scan/saml_response_time_bomb")
@vl_turbo()
@vl_verify()
def scan_saml_response_time_bomb(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    metadata_xml = None
    metadata_url = None
    for path in META_PATHS:
        r = safe_request("GET", base + path,
            headers={"User-Agent": "VulnusLab/1.0"},
            req=req, timeout=8, allow_redirects=False)
        if r is None or r.status_code != 200: continue
        body = (r.text or "")[:100000]
        if "EntityDescriptor" in body and ("SPSSODescriptor" in body or "IDPSSODescriptor" in body):
            metadata_xml = body
            metadata_url = base + path
            break

    if not metadata_xml:
        return standard_response(
            tool="saml_response_time_bomb", target=req.target, findings=[],
            tests_performed=len(META_PATHS), vulnerable=False,
            skipped_reason="No SAML metadata at common paths — see saml_xml_signature_wrap "
                            "for non-metadata SAML detection")

    findings = []
    issues = []

    # Audit 1: validUntil attribute (controls metadata validity)
    m = re.search(r'validUntil="([^"]+)"', metadata_xml)
    valid_until = m.group(1) if m else None
    if not valid_until:
        issues.append(("metadata missing validUntil — never expires", "MEDIUM"))

    # Audit 2: cacheDuration too long
    m = re.search(r'cacheDuration="([^"]+)"', metadata_xml)
    cache_dur = m.group(1) if m else None
    if cache_dur and "Y" in cache_dur:  # P1Y / P10Y etc.
        issues.append((f"metadata cacheDuration={cache_dur} — multi-year cache", "LOW"))

    # Audit 3: X509Certificate count
    certs = re.findall(r'<ds:X509Certificate[^>]*>([^<]+)</ds:X509Certificate>', metadata_xml)
    if not certs:
        issues.append(("No X509Certificate in metadata — RP can't verify assertions", "HIGH"))

    # Audit 4: WantAssertionsSigned attribute
    if "WantAssertionsSigned=\"true\"" not in metadata_xml \
            and "WantAssertionsSigned='true'" not in metadata_xml:
        issues.append(("SPSSODescriptor missing WantAssertionsSigned='true' — accepts "
                        "unsigned assertions", "HIGH"))

    # Audit 5: AuthnRequestsSigned
    if "AuthnRequestsSigned=\"true\"" not in metadata_xml \
            and "AuthnRequestsSigned='true'" not in metadata_xml:
        issues.append(("AuthnRequestsSigned NOT set true — IdP can't verify SP-side "
                        "AuthnRequest authenticity", "MEDIUM"))

    if issues:
        sev = "HIGH" if any(s == "HIGH" for _, s in issues) else "MEDIUM"
        cvss = "7.5" if sev == "HIGH" else "5.3"
        findings.append(wrap_finding(
            f"SAML metadata audit: {len(issues)} issue(s)",
            sev, cvss=cvss, cwe="CWE-345", owasp="A07:2021",
            remediation="(1) Set validUntil to a realistic horizon (1y max). "
                        "(2) Set WantAssertionsSigned=true on SPSSODescriptor. "
                        "(3) Set AuthnRequestsSigned=true. (4) Include at least "
                        "one signing X509Certificate. (5) Audit NotOnOrAfter "
                        "tolerance in your SAML lib config — should be ≤5 min "
                        "skew to limit replay window.",
            evidence_marker=" | ".join(f"{m} [{s}]" for m, s in issues[:5])))
    else:
        findings.append(wrap_finding(
            "SAML metadata properly hardened",
            "POSITIVE", cwe="CWE-345",
            remediation="Maintain. Rotate signing cert annually.",
            evidence_marker=f"metadata_url: {metadata_url}, "
                              f"certs: {len(certs)}, validUntil: {valid_until}"))

    return standard_response(
        tool="saml_response_time_bomb", target=req.target, findings=findings,
        tests_performed=len(META_PATHS), vulnerable=bool(issues),
        tests_summary=f"metadata at {metadata_url}, {len(issues)} issues",
        raw_data={"metadata_url": metadata_url,
                   "valid_until": valid_until,
                   "cache_duration": cache_dur,
                   "cert_count": len(certs),
                   "issues": [{"desc": m, "severity": s} for m, s in issues]})


def register(app):
    app.include_router(router)
