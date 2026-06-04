"""saml_signature_audit - findings rules.

Severity model:
  CRITICAL - any forged SAMLResponse accepted by the SP's ACS endpoint
  INFO     - missing input / no Assertion / httpx unavailable
  POSITIVE - all 4 variants rejected by the SP
"""


def rule_critical_accepted(s):
    accepted = s.get("saml_accepted_variants") or []
    if not accepted:
        return None
    results = s.get("saml_variant_results") or []
    acs = s.get("saml_acs_url") or "?"
    accepted_lines = []
    for r in results:
        if r.get("accepted"):
            accepted_lines.append(
                f"{r.get('variant')} -> HTTP {r.get('status')} "
                f"set-cookie={r.get('set_cookie')} redirect={r.get('redirect_to', '')[:80]!r}"
            )
    return {
        "name": f"SAML signature bypass: {len(accepted)} forged response(s) accepted by ACS",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-347",
        "owasp": "A07:2021",
        "evidence": (
            f"The Service Provider at {acs} accepted the following forged "
            f"SAMLResponse variants: {', '.join(accepted)}. "
            "Detail: " + " | ".join(accepted_lines) + ". "
            "Any of these allows full authentication bypass."
        ),
        "remediation": (
            "1. Patch the SAML library: python3-saml >=1.16.0 / OneLogin Toolkits / passport-saml etc. "
            "2. Validate that EXACTLY ONE Signature exists and covers the Assertion AND the Response. "
            "3. Enforce strict ID-based reference checking - reject any Assertion whose ID differs from the signed reference. "
            "4. Reject any Assertion containing XML comments inside NameID / AttributeValue elements. "
            "5. Pin the trusted IdP certificate fingerprint server-side; never trust an embedded X509Certificate. "
            "6. Re-run this scan after the fix - any accepted variant is a re-issue."
        ),
    }


def rule_input_missing(s):
    if not s.get("saml_input_missing"):
        return None
    return {
        "name": "SAML signature audit skipped - no sample response / ACS URL",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": (
            "This probe requires options.saml_response (the base64 or raw XML SAMLResponse "
            "from a successful login) and options.saml_acs_url (the SP endpoint that "
            "consumes the response). Without both, the audit cannot run."
        ),
        "remediation": (
            "Capture a SAMLResponse from a valid login using browser devtools / SAML-tracer, "
            "paste it into options.saml_response, set options.saml_acs_url to the SP's POST "
            "endpoint, and re-run."
        ),
    }


def rule_malformed(s):
    if not s.get("saml_malformed"):
        return None
    return {
        "name": "Supplied SAMLResponse does not contain an Assertion element",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": "The decoded XML lacked a <saml:Assertion> tag, so signature/wrapping attacks are not applicable.",
        "remediation": (
            "Confirm the captured response is the full SAMLResponse (not just the LogoutResponse / "
            "metadata) and that it was decoded from the HTTP-POST binding correctly."
        ),
    }


def rule_httpx_missing(s):
    if not s.get("saml_httpx_missing"):
        return None
    return {
        "name": "httpx library not installed on scanner host",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": "`import httpx` failed - required to send forged responses to the ACS endpoint.",
        "remediation": "pip install httpx >=0.24 inside the scanner container.",
    }


def rule_positive(s):
    if s.get("saml_input_missing"):
        return None
    if s.get("saml_malformed"):
        return None
    if s.get("saml_httpx_missing"):
        return None
    if (s.get("saml_accepted_variants") or []):
        return None
    results = s.get("saml_variant_results") or []
    if not results:
        return None
    return {
        "name": "SAML SP rejected all 4 signature-bypass variants",
        "severity": "POSITIVE",
        "cwe": "CWE-347",
        "owasp": "A07:2021",
        "evidence": (
            f"Stripping, XSW1 wrapping, XML-comment injection, and cert confusion were "
            f"all rejected by the ACS at {s.get('saml_acs_url', '?')}. Status codes: " +
            ", ".join(f"{r.get('variant')}={r.get('status')}" for r in results) + "."
        ),
        "remediation": (
            "Keep the SAML library patched (subscribe to OneLogin / OASIS advisories). Re-run after "
            "every IdP cert rotation - misconfigured rotations have re-introduced this bug in production."
        ),
    }


SAML_SIGNATURE_AUDIT_FINDING_RULES = [
    rule_critical_accepted,
    rule_input_missing,
    rule_malformed,
    rule_httpx_missing,
    rule_positive,
]
