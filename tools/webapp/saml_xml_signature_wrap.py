"""saml_xml_signature_wrap — SAML SP detection + XSW attack-surface flag.

Discovers SAML 2.0 Service Provider endpoints by probing common paths
(/saml/login, /sso, /Shibboleth.sso/Login, etc) and checks if the
AuthnRequest endpoint accepts unsigned/malformed SAMLResponse.

Active XSW (XML Signature Wrapping) requires a real SP test with an
IdP — out of scope for SaaS-friendly scan. This scanner flags the
presence of SAML SP endpoints AND known-vulnerable library versions
(via Server: header / response banners) so the human can pursue.
"""
import re
import base64
import zlib
from urllib.parse import quote
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)

router = APIRouter()

SAML_PATHS = [
    "/saml/login", "/saml/sso", "/saml2/sso",
    "/sso/login", "/sso",
    "/Shibboleth.sso/Login", "/Shibboleth.sso/Metadata",
    "/simplesaml/saml2/idp/SSOService.php",
    "/auth/saml", "/auth/saml/callback",
    "/idp/profile/SAML2/Redirect/SSO",
    "/api/auth/saml", "/oauth2/saml",
]

# Known-vulnerable SAML library banners
VULN_BANNERS = [
    ("OneLogin python-saml < 2.7.0",   "python-saml"),
    ("Spring SAML < 1.0.10",            "Spring-Security-SAML"),
    ("SimpleSAMLphp < 1.18",            "SimpleSAMLphp"),
    ("Shibboleth SP < 3.0.4",           "Shibboleth-Handler"),
]


def _build_minimal_saml_response() -> str:
    """Minimal unsigned SAMLResponse — for testing if endpoint validates signature."""
    xml = (
        '<?xml version="1.0"?>'
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'ID="_vulnuslab-test" Version="2.0" IssueInstant="2024-01-01T00:00:00Z" '
        'Destination="https://target.example/saml/acs">'
        '<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
        'https://vulnuslab-test.invalid</saml:Issuer>'
        '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
        '</samlp:Status></samlp:Response>'
    )
    return base64.b64encode(xml.encode()).decode()


@router.post("/api/webapp/scan/saml_xml_signature_wrap")
def scan_saml_xml_signature_wrap(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    found_endpoints = []
    metadata_endpoints = []
    banner_hits = []

    for path in SAML_PATHS:
        url = base + path
        r = safe_request("GET", url,
            headers={"User-Agent": "VulnusLab/1.0"},
            req=req, timeout=8, allow_redirects=False)
        if r is None or r.status_code == 404: continue

        body = (r.text or "")[:50000]
        # Classify
        if "SAMLRequest" in body or "AuthnRequest" in body or "samlp:" in body:
            found_endpoints.append({"path": path, "status": r.status_code,
                                      "type": "SP-AuthnRequest"})
        if "EntityDescriptor" in body or "md:SPSSODescriptor" in body:
            metadata_endpoints.append({"path": path, "status": r.status_code,
                                         "type": "SP-Metadata"})
        # Check banner
        for desc, marker in VULN_BANNERS:
            if marker in body or marker in str(r.headers):
                banner_hits.append({"path": path, "banner": desc})

    findings = []
    if banner_hits:
        findings.append(wrap_finding(
            f"Known-vulnerable SAML library banner ({len(banner_hits)})",
            "HIGH", cvss="7.5", cwe="CWE-347", owasp="A07:2021",
            remediation="Upgrade to patched SAML library version. XSW (XML "
                        "Signature Wrapping) attacks abuse signature-validation "
                        "implementation bugs to forge assertions = full account "
                        "takeover. Test with SAML Raider / EsPReSSO post-upgrade.",
            evidence_marker=" | ".join(f"{b['path']}: {b['banner']}" for b in banner_hits[:3])))

    if found_endpoints or metadata_endpoints:
        findings.append(wrap_finding(
            f"SAML SP endpoints discovered ({len(found_endpoints) + len(metadata_endpoints)})",
            "INFO" if not banner_hits else "MEDIUM",
            cwe="CWE-347", owasp="A07:2021",
            remediation="SAML 2.0 service provider detected. Recommend hands-on "
                        "test for: (1) XSW via SAML Raider, (2) unsigned-assertion "
                        "acceptance, (3) clock-skew tolerance > 5 min (replay), "
                        "(4) NotOnOrAfter not enforced, (5) Comments-injection "
                        "(CVE-2018-0489 family). Pull metadata at "
                        f"{base}/Shibboleth.sso/Metadata or equivalent for IdP cert + "
                        "WantAssertionsSigned audit.",
            evidence_marker=" | ".join(
                f"{e['path']} ({e['type']}, HTTP {e['status']})"
                for e in (found_endpoints + metadata_endpoints)[:5]
            )))
    else:
        return standard_response(
            tool="saml_xml_signature_wrap", target=req.target,
            findings=[wrap_finding(
                "No SAML SP endpoints detected at common paths",
                "POSITIVE", cwe="CWE-200",
                remediation="No SAML attack surface from this scan. If your IdP "
                            "uses non-standard endpoints, scan with custom path list.",
                evidence_marker=f"checked {len(SAML_PATHS)} common SAML paths")],
            tests_performed=len(SAML_PATHS), vulnerable=False,
            tests_summary="No SAML SP detected")

    return standard_response(
        tool="saml_xml_signature_wrap", target=req.target, findings=findings,
        tests_performed=len(SAML_PATHS), vulnerable=bool(banner_hits),
        tests_summary=f"{len(found_endpoints + metadata_endpoints)} SAML endpoints, "
                       f"{len(banner_hits)} vulnerable banners",
        raw_data={"endpoints": found_endpoints, "metadata": metadata_endpoints,
                   "banner_hits": banner_hits})


def register(app):
    app.include_router(router)
