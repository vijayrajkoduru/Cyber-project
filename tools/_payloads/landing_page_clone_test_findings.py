"""landing_page_clone_test - findings rules.

This probe doesn't break anything on the customer's stack — it
generates an attacker-perspective artifact. The single substantive
finding is INFO: here is the clone, here is what made it easy.

Severity model:
  INFO  - customer didn't supply options.target_url
  INFO  - dependency missing (httpx / bs4)
  INFO  - fetch failed
  INFO  - no <form> found on target_url (probe still reports headers)
  INFO  - clone produced (here is the HTML + the attackability factors)
"""

_CWE_VERIFY = "CWE-345"   # Insufficient Verification of Data Authenticity
_CWE_SPOOF  = "CWE-290"   # Authentication Bypass by Spoofing
_NIST = "NIST 800-53 SC-8 (Transmission Confidentiality and Integrity)"


def rule_input_missing(s):
    if not s.get("clone_input_missing"):
        return None
    return {
        "name": "Landing-page clone probe skipped - no options.target_url supplied",
        "severity": "INFO",
        "evidence": (
            "This probe requires the customer to supply the URL of "
            "their real login page via options.target_url (e.g. "
            "https://acme.com/login). Without it, the probe has "
            "nothing to clone."
        ),
        "remediation": (
            "Re-run with options.target_url set to your login page. "
            "The probe never sends, hosts or stores the clone — it is "
            "returned to you as a text artifact only."
        ),
        "cwe": "CWE-1006",
    }


def rule_dep_missing(s):
    err = s.get("clone_error") or ""
    if "not installed" not in err.lower():
        return None
    return {
        "name": "Landing-page clone probe skipped - missing Python dependency",
        "severity": "INFO",
        "evidence": err,
        "remediation": (
            "Install the missing dep on the scanner host: "
            "pip install httpx beautifulsoup4. Then re-run."
        ),
        "cwe": "CWE-1006",
    }


def rule_fetch_failed(s):
    err = s.get("clone_error") or ""
    if "fetch failed" not in err.lower():
        return None
    return {
        "name": "Landing-page clone probe failed - couldn't fetch target_url",
        "severity": "INFO",
        "evidence": err,
        "remediation": (
            "Confirm the URL is reachable from the scanner egress IP. "
            "If your login page is behind WAF/geo-block, whitelist the "
            "scanner IP for this probe."
        ),
        "cwe": "CWE-1006",
    }


def rule_no_form(s):
    if not s.get("clone_no_form"):
        return None
    return {
        "name": "Login form not detected on target_url",
        "severity": "INFO",
        "evidence": (
            f"GET {s.get('clone_target_url')} returned status "
            f"{s.get('clone_http_status')} but no <form> tag containing "
            "an input[type=password] was found in the rendered HTML. "
            "This typically means the page is a single-page-app that "
            "renders the form via JS after load — the static fetch "
            "didn't see it."
        ),
        "remediation": (
            "Re-run after pointing options.target_url at the page that "
            "actually serves the password input as static HTML (look "
            "for an internal /signin or /auth endpoint). For SPA-rendered "
            "forms, use a browser-automation clone tool like "
            "`httrack`, `gophish import url` or a full headless browser."
        ),
        "cwe": _CWE_SPOOF,
    }


def rule_clone_artifact(s):
    html = s.get("clone_html")
    if not html:
        return None
    csrf = s.get("clone_csrf") or {}
    sri = s.get("clone_sri") or {}
    sec = s.get("clone_security_headers") or {}
    fa = s.get("clone_frame_ancestors")
    fields = s.get("clone_field_count", 0)
    score = s.get("clone_attackability_score", 0)
    preview = html[:600] + ("..." if len(html) > 600 else "")
    return {
        "name": (f"Login-page clone produced for "
                 f"{s.get('clone_target_url', '?')} (artifact - no deploy)"),
        "severity": "INFO",
        "cwe": _CWE_SPOOF,
        "cwe_name": "Authentication Bypass by Spoofing",
        "owasp": "A07:2021",
        "evidence": (
            f"Source HTML: {s.get('clone_html_byte_len', 0)}B. "
            f"Clone HTML: {s.get('clone_html_byte_len_out', 0)}B. "
            f"Form action: {s.get('clone_form_action', '?')}. "
            f"Form fields enumerated: {fields}. "
            f"CSRF token: {'detected' if csrf.get('present') else 'NOT detected'}. "
            f"Subresource integrity: {sri.get('with_sri', 0)}/"
            f"{sri.get('external_scripts', 0)} external scripts. "
            f"CSP frame-ancestors: {fa or 'NOT set'}. "
            f"Security headers present: "
            f"{', '.join(sorted(sec.keys())) or 'none'}. "
            f"Attackability score (0=hardest, 20=trivial): {score}. "
            f"Clone HTML preview: {preview}"
        ),
        "remediation": (
            "1. Add `Content-Security-Policy: frame-ancestors 'self'` "
            "to the login page response so a phishing site cannot "
            "embed it in an iframe (Browser-in-the-Browser defense). "
            "2. Subscribe to Certificate Transparency feeds (crt.sh "
            "RSS or Cloudflare CT-Streamer) filtered to your brand "
            "keywords so newly-issued certs for `secure-<brand>.com` "
            "trigger a SOC ticket. "
            "3. Add `Subresource-Integrity` (SRI) hashes to every "
            "external <script src=> on the login page so an attacker "
            "cloning the page cannot silently swap your analytics JS "
            "for a keylogger. "
            "4. Set `autocomplete='off'` and `autocomplete='new-password'` "
            "appropriately to prevent password-manager mis-fill on "
            "lookalike domains. "
            "5. Enable phishing-resistant MFA (FIDO2 / passkeys) on "
            "the login flow — even a perfect clone cannot replay a "
            "WebAuthn assertion. "
            f"6. Train staff: any password-reset email must be "
            "verified by typing the URL manually, not clicking. "
            f"Compliance: {_NIST}, OWASP ASVS 4.0 V2.5 (Sign-in)."
        ),
    }


LANDING_PAGE_CLONE_TEST_FINDING_RULES = [
    rule_input_missing,
    rule_dep_missing,
    rule_fetch_failed,
    rule_no_form,
    rule_clone_artifact,
]
