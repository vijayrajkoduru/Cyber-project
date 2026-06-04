"""oauth_redirect_audit - findings rules.

Severity model:
  CRITICAL - any mutated redirect_uri accepted -> auth-code can be stolen
  HIGH     - baseline rejected (config issue) or response_type=token observed
  INFO     - missing input / httpx unavailable
  POSITIVE - all mutations rejected
"""


def rule_critical_accepted(s):
    accepted = s.get("oauth_accepted_attacks") or []
    if not accepted:
        return None
    results = s.get("oauth_variant_results") or []
    accepted_lines = []
    for r in results:
        if r.get("accepted"):
            accepted_lines.append(
                f"{r.get('attack')} -> Location: {r.get('location', '')[:120]!r}"
            )
    return {
        "name": f"OAuth redirect_uri validation bypass: {len(accepted)} mutation(s) accepted",
        "severity": "CRITICAL",
        "cvss": "9.6",
        "cwe": "CWE-601",
        "owasp": "A01:2021",
        "evidence": (
            f"The Authorization Server at {s.get('oauth_authorize_url', '?')} accepted "
            f"the following malicious redirect_uri values and bounced the auth code to "
            f"an attacker-controlled host: {', '.join(accepted)}. "
            "Detail: " + " | ".join(accepted_lines) + ". "
            "Stealing the auth code = full account takeover."
        ),
        "remediation": (
            "1. Pin redirect_uri to a strict allowlist of EXACT URIs (string-compare, not prefix/regex). "
            "2. Reject any redirect_uri that contains '@', '..', '\\', or that resolves to a different host. "
            "3. Disable javascript: and data: schemes at the AS layer. "
            "4. Validate redirect_uri server-side BEFORE issuing the code, not after. "
            "5. Follow RFC 6749 Section 3.1.2 + RFC 9700 (OAuth 2.0 Security BCP). "
            "6. Re-run this scan after the fix - any single mutation still accepted means recheck."
        ),
    }


def rule_input_missing(s):
    if not s.get("oauth_input_missing"):
        return None
    return {
        "name": "OAuth redirect audit skipped - missing required options",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": (
            "Probe requires options.oauth_authorize_url + options.client_id + options.original_redirect. "
            "Without them no /authorize requests can be sent."
        ),
        "remediation": (
            "Re-run with all three populated. Tip: copy a real /authorize URL from a browser "
            "devtools network trace, extract client_id + redirect_uri from the query string."
        ),
    }


def rule_httpx_missing(s):
    if not s.get("oauth_httpx_missing"):
        return None
    return {
        "name": "httpx library not installed on scanner host",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": "`import httpx` failed - required to send /authorize requests.",
        "remediation": "pip install httpx >=0.24 inside the scanner container.",
    }


def rule_positive(s):
    if s.get("oauth_input_missing"):
        return None
    if s.get("oauth_httpx_missing"):
        return None
    if (s.get("oauth_accepted_attacks") or []):
        return None
    tried = s.get("oauth_mutations_tried") or 0
    if not tried:
        return None
    return {
        "name": f"OAuth Authorization Server rejected all {tried} redirect_uri mutations",
        "severity": "POSITIVE",
        "cwe": "CWE-601",
        "owasp": "A01:2021",
        "evidence": (
            f"Subdomain takeover, open-redirect chain, path traversal, userinfo bypass, "
            f"HTTP downgrade, scheme confusion, trailing-dot bypass and port confusion all "
            f"returned errors or were not bounced to attacker hosts (baseline status: "
            f"{s.get('oauth_baseline_status', '?')})."
        ),
        "remediation": (
            "Keep the redirect_uri allowlist locked to exact strings. Re-run after every IdP "
            "config change or new OAuth client registration."
        ),
    }


OAUTH_REDIRECT_AUDIT_FINDING_RULES = [
    rule_critical_accepted,
    rule_input_missing,
    rule_httpx_missing,
    rule_positive,
]
