"""oauth_token_audit - finding rules (VL-METHOD aware).

OAuth 2.0 / OIDC token endpoint misconfiguration audit. Reads state
populated by OauthTokenAudit's 7-stage flow:

  - methodology_findings   : list of confirmed/suspected misconfigs
  - target_base            : base URL of the OAuth IdP
  - discovery_doc_url      : URL of /.well-known/* document
  - authorize_endpoint     : OAuth authorize endpoint
  - token_endpoint         : OAuth token endpoint
  - fingerprint            : provider info {provider, response_types,
                              grant_types, pkce_supported, supports_implicit}
  - quick_probe_attempts   : number of quick-probe tests run
  - quick_probe_hits       : number of misconfigs found in quick_probe
  - chain_next             : downstream scanner handoffs
  - skipped_reason         : pre_flight skip reason

Severity model:
  CONFIRMED open_redirect_via_redirect_uri    -> CRITICAL CVSS 9.4
  CONFIRMED implicit_flow_enabled             -> HIGH     CVSS 8.1
  CONFIRMED excessive_scope_accepted          -> HIGH     CVSS 8.1
  CONFIRMED missing_state_csrf                -> HIGH     CVSS 7.5
  CONFIRMED pkce_not_enforced                 -> HIGH     CVSS 7.5
  CONFIRMED refresh_rotation_disabled         -> MEDIUM   CVSS 6.5
  fingerprint.supports_implicit (advisory)    -> MEDIUM   CVSS 5.3
  fingerprint.pkce_supported=False (advisory) -> MEDIUM   CVSS 5.3
  SUSPECTED any                                -> LOW      CVSS 3.7
  Zero misconfigs + clean posture              -> POSITIVE
  Input missing / no OAuth discovered          -> INFO
"""


INTEL_FIELDS = [
    ("Target URL",                "target_base"),
    ("OAuth Discovery Doc",       "discovery_doc_url"),
    ("Authorize Endpoint",        "authorize_endpoint"),
    ("Token Endpoint",            "token_endpoint"),
    ("Provider Info",             "fingerprint"),
    ("Quick-probe tests",         "quick_probe_attempts"),
    ("Misconfigurations found",   "quick_probe_hits"),
    ("Stage timings (ms)",        "stage_timings"),
    ("Stage errors",              "stage_errors"),
    ("Chain ID",                  "chain_id"),
]


# ── helper: group methodology_findings by attack class + confidence ──


def _findings_by_attack_class(s):
    """Group methodology_findings into buckets keyed by attack_class.

    Each bucket holds CONFIRMED and SUSPECTED lists separately so the
    severity rules can pick the right tier.
    """
    out = {}
    for f in (s.get("methodology_findings") or []):
        attack = f.get("attack_class") or "unknown"
        conf = f.get("confidence", "SUSPECTED")
        bucket = out.setdefault(attack, {"CONFIRMED": [], "SUSPECTED": []})
        if conf == "CONFIRMED":
            bucket["CONFIRMED"].append(f)
        else:
            bucket["SUSPECTED"].append(f)
    return out


# ── INFO rules: pre_flight skip + input missing ──


def rule_no_oauth_discovered(s):
    reason = (s.get("skipped_reason") or "").lower()
    if "no oauth/oidc endpoint discovered" not in reason:
        return None
    return {
        "name":     "No OAuth/OIDC endpoint discovered at standard paths",
        "severity": "INFO",
        "evidence": (f"Probed /.well-known/openid-configuration, "
                     f"/.well-known/oauth-authorization-server, and common "
                     f"authorize paths on {s.get('target_base') or 'target'} - "
                     f"none responded as an OAuth/OIDC provider."),
        "remediation": ("If this target is supposed to expose an OAuth/OIDC "
                        "interface, verify the discovery document is "
                        "reachable at /.well-known/openid-configuration. "
                        "If OAuth is NOT exposed here, this is expected and "
                        "no action is needed."),
        "cwe": "CWE-1006",
    }


def rule_input_missing(s):
    reason = (s.get("skipped_reason") or "").lower()
    if "requires target url" not in reason:
        return None
    return {
        "name":     "OAuth token audit skipped - no target URL provided",
        "severity": "INFO",
        "evidence": ("Scanner requires a target base URL of the OAuth IdP "
                     "or OIDC provider (e.g. https://idp.example.com). No "
                     "target was supplied in the scan request."),
        "remediation": ("Supply the base URL of your OAuth/OIDC provider "
                        "via the target field on the scan request."),
        "cwe": "CWE-1006",
    }


# ── Advisory rules: fingerprint-derived metadata findings ──


def rule_implicit_supported_warning(s):
    """NEW - provider advertises implicit flow but no exploit confirmed."""
    fp = s.get("fingerprint") or {}
    if not fp.get("supports_implicit"):
        return None
    # Skip if we already CONFIRMED implicit flow live - that finding
    # speaks for itself at HIGH severity.
    groups = _findings_by_attack_class(s)
    if groups.get("implicit_flow_enabled", {}).get("CONFIRMED"):
        return None
    return {
        "name":     "OAuth provider advertises support for implicit flow (response_type=token)",
        "severity": "MEDIUM",
        "cvss":     "5.3",
        "cwe":      "CWE-358",
        "evidence": (f"discovery doc response_types_supported includes "
                     f"implicit-flow values: {fp.get('response_types')}. "
                     f"Provider: {fp.get('provider')}, issuer: "
                     f"{fp.get('issuer')}. RFC 8252 (OAuth 2.0 for Native "
                     f"Apps) deprecates the implicit flow because access "
                     f"tokens leak via Referer headers and browser history."),
        "remediation": ("Remove 'token' and 'id_token token' from "
                        "response_types_supported in the OAuth/OIDC "
                        "configuration. Migrate all clients to "
                        "authorization_code + PKCE (S256). If a legacy "
                        "client still requires implicit, scope it to a "
                        "single deprecated client_id and plan migration."),
    }


def rule_pkce_not_supported(s):
    """Provider does NOT advertise PKCE in discovery doc."""
    fp = s.get("fingerprint") or {}
    # Only fire if we actually read a discovery doc (else absence of PKCE
    # field is just absence of doc)
    if not s.get("discovery_doc_url"):
        return None
    if fp.get("pkce_supported"):
        return None
    return {
        "name":     "OAuth provider does NOT advertise PKCE support",
        "severity": "MEDIUM",
        "cvss":     "5.3",
        "cwe":      "CWE-345",
        "evidence": (f"discovery doc at {s.get('discovery_doc_url')} omits "
                     f"code_challenge_methods_supported (or lists none). "
                     f"Public clients (SPAs, mobile apps) cannot protect "
                     f"against authorization-code interception without PKCE."),
        "remediation": ("Enable PKCE on the OAuth/OIDC provider and "
                        "advertise it in the discovery document: "
                        "\"code_challenge_methods_supported\": [\"S256\"]. "
                        "Then enforce PKCE for all public clients - reject "
                        "authorize requests from public clients that omit "
                        "code_challenge."),
    }


# ── POSITIVE rule: clean baseline ──


def rule_clean_oauth_posture(s):
    """0 misconfigs + PKCE supported + no implicit + all 5 quick probes rejected."""
    if (s.get("methodology_total") or 0) > 0:
        return None
    if (s.get("quick_probe_attempts") or 0) < 5:
        return None
    if (s.get("quick_probe_hits") or 0) > 0:
        return None
    fp = s.get("fingerprint") or {}
    if not fp.get("pkce_supported"):
        return None
    if fp.get("supports_implicit"):
        return None
    return {
        "name":     "OAuth/OIDC provider follows modern security baseline",
        "severity": "POSITIVE",
        "evidence": (f"Provider {fp.get('provider')} at "
                     f"{s.get('target_base')} passed all 5 quick-probe "
                     f"misconfiguration tests (missing state, implicit flow, "
                     f"open redirect via redirect_uri, PKCE enforcement, "
                     f"excessive scope). Discovery doc advertises PKCE "
                     f"({fp.get('pkce_supported')}) and does NOT advertise "
                     f"implicit flow."),
        "remediation": ("Maintain current OAuth/OIDC posture. Continue "
                        "monitoring for client mis-registrations (over-"
                        "broad redirect_uri patterns, public clients "
                        "registered as confidential, etc.) via periodic "
                        "automated audits."),
        "cwe": "CWE-345",
        "owasp": "A07:2021",
    }


# ── CONFIRMED rules (per attack class) ──


def rule_confirmed_open_redirect(s):
    g = _findings_by_attack_class(s)
    confirmed = g.get("open_redirect_via_redirect_uri", {}).get("CONFIRMED") or []
    if not confirmed:
        return None
    vectors = sorted({f.get("bypass_vector", "unknown") for f in confirmed})
    return {
        "name":     f"CONFIRMED open redirect via redirect_uri ({len(confirmed)} bypass vector{'s' if len(confirmed) > 1 else ''})",
        "severity": "CRITICAL",
        "cvss":     "9.4",
        "cwe":      "CWE-601",
        "owasp":    "A01:2021",
        "evidence": (f"OAuth authorize endpoint accepts attacker-controlled "
                     f"redirect_uri values, enabling account takeover via "
                     f"OAuth phishing. Bypass vectors that worked: "
                     f"{', '.join(vectors)}. Re-tested with a different "
                     f"attacker domain - reproduced (CONFIRMED)."),
        "remediation": ("Enforce EXACT-MATCH validation of redirect_uri "
                        "against the client's registered redirect_uris "
                        "(RFC 6749 4.1.2.1). Do NOT accept subdomain, "
                        "wildcard, path-traversal, or fragment-trick "
                        "variants. Reject any authorize request whose "
                        "redirect_uri does not byte-for-byte match a "
                        "pre-registered URI."),
    }


def rule_confirmed_missing_state(s):
    g = _findings_by_attack_class(s)
    confirmed = g.get("missing_state_csrf", {}).get("CONFIRMED") or []
    if not confirmed:
        return None
    return {
        "name":     "CONFIRMED missing state parameter enforcement",
        "severity": "HIGH",
        "cvss":     "7.5",
        "cwe":      "CWE-352",
        "owasp":    "A01:2021",
        "evidence": ("OAuth authorize endpoint issues authorization codes "
                     "even when the request omits the 'state' parameter. "
                     "Re-tested with a different client_id - reproduced "
                     "(CONFIRMED). This enables CSRF on the OAuth callback, "
                     "allowing attackers to bind their account to a "
                     "victim's session."),
        "remediation": ("Require the 'state' parameter on every authorize "
                        "request. Reject requests that omit it with "
                        "HTTP 400 + error=invalid_request. Verify the state "
                        "echoed back on the callback matches the value "
                        "stored in the client's session."),
    }


def rule_confirmed_implicit_flow_live(s):
    g = _findings_by_attack_class(s)
    confirmed = g.get("implicit_flow_enabled", {}).get("CONFIRMED") or []
    if not confirmed:
        return None
    return {
        "name":     "CONFIRMED implicit flow enabled (response_type=token issues access tokens)",
        "severity": "HIGH",
        "cvss":     "8.1",
        "cwe":      "CWE-294",
        "owasp":    "A07:2021",
        "evidence": ("OAuth authorize endpoint accepts response_type=token "
                     "and returns access tokens directly in the URL "
                     "fragment. Re-tested with response_type='id_token "
                     "token' - reproduced (CONFIRMED). Implicit flow is "
                     "deprecated by RFC 8252; access tokens leak via "
                     "Referer headers, browser history, and server logs."),
        "remediation": ("Disable the implicit flow on the OAuth/OIDC "
                        "provider. Remove 'token' and 'id_token token' "
                        "from response_types_supported. Migrate all "
                        "clients to authorization_code + PKCE (S256). "
                        "Public clients (SPAs, mobile) MUST use PKCE."),
    }


def rule_confirmed_pkce_not_enforced(s):
    g = _findings_by_attack_class(s)
    confirmed = g.get("pkce_not_enforced", {}).get("CONFIRMED") or []
    if not confirmed:
        return None
    return {
        "name":     "CONFIRMED PKCE not enforced (code grant accepted without code_challenge)",
        "severity": "HIGH",
        "cvss":     "7.5",
        "cwe":      "CWE-345",
        "owasp":    "A07:2021",
        "evidence": ("OAuth authorize endpoint accepts response_type=code "
                     "requests that omit the code_challenge parameter. "
                     "Re-tested with a different client_id - reproduced "
                     "(CONFIRMED). Authorization codes can be intercepted "
                     "on the redirect (custom URL scheme, malicious app, "
                     "shoulder surf) and exchanged for tokens without PKCE "
                     "proof-of-possession."),
        "remediation": ("Enforce PKCE for all public clients. Reject "
                        "authorize requests from public client_ids that "
                        "omit code_challenge with HTTP 400 + "
                        "error=invalid_request. Confidential clients with "
                        "a server-side client_secret may keep PKCE "
                        "optional, but RFC 9700 (OAuth 2.0 Security BCP) "
                        "recommends PKCE for ALL clients."),
    }


def rule_confirmed_refresh_not_rotated(s):
    g = _findings_by_attack_class(s)
    confirmed = g.get("refresh_rotation_disabled", {}).get("CONFIRMED") or []
    if not confirmed:
        return None
    return {
        "name":     "CONFIRMED refresh token rotation not enforced",
        "severity": "MEDIUM",
        "cvss":     "6.5",
        "cwe":      "CWE-613",
        "owasp":    "A07:2021",
        "evidence": ("Token endpoint returned successful responses for "
                     "synthetic refresh_token values on multiple attempts. "
                     "This indicates refresh tokens are NOT rotated (the "
                     "same refresh token can be exchanged multiple times) "
                     "or the endpoint accepts unverified refresh tokens. "
                     "Re-tested with a different synthetic token - "
                     "reproduced (CONFIRMED)."),
        "remediation": ("Enable refresh token rotation: every refresh_token "
                        "exchange returns a new refresh_token AND "
                        "invalidates the old one. Detect re-use of "
                        "rotated-out refresh tokens and revoke the entire "
                        "token family on detection (RFC 9700 4.13). "
                        "Bind refresh tokens to client + user + device "
                        "fingerprint."),
    }


def rule_confirmed_scope_escalation(s):
    g = _findings_by_attack_class(s)
    confirmed = g.get("excessive_scope_accepted", {}).get("CONFIRMED") or []
    if not confirmed:
        return None
    return {
        "name":     "CONFIRMED excessive scope accepted without consent",
        "severity": "HIGH",
        "cvss":     "8.1",
        "cwe":      "CWE-863",
        "owasp":    "A01:2021",
        "evidence": ("OAuth authorize endpoint accepts scope values like "
                     "'admin', 'root', 'superuser' without surfacing a "
                     "consent prompt or returning invalid_scope. "
                     "Re-tested with a different excessive scope set - "
                     "reproduced (CONFIRMED). Attackers can phish users "
                     "into authorizing apps with admin-level access."),
        "remediation": ("Reject unknown scopes with error=invalid_scope. "
                        "Require explicit user consent for any scope "
                        "beyond the baseline (openid, profile, email). "
                        "Maintain a strict allowlist of scopes per "
                        "client_id - never accept arbitrary scope "
                        "values from the authorize request."),
    }


# ── SUSPECTED rule: any verify-failed finding ──


def rule_suspected_oauth_misconfig(s):
    g = _findings_by_attack_class(s)
    suspected = []
    for attack, bucket in g.items():
        suspected.extend(bucket.get("SUSPECTED") or [])
    if not suspected:
        return None
    classes = sorted({f.get("attack_class") or "unknown" for f in suspected})
    return {
        "name":     f"SUSPECTED OAuth misconfiguration ({len(suspected)} - needs manual verification)",
        "severity": "LOW",
        "cvss":     "3.7",
        "cwe":      "CWE-1006",
        "owasp":    "A07:2021",
        "evidence": (f"Quick-probe detected potential misconfiguration(s) "
                     f"that did NOT reproduce on the verify re-test. "
                     f"Attack classes flagged: {', '.join(classes)}. "
                     f"Could be intermittent behaviour, rate-limiting "
                     f"interfering with verify, or true false-positive."),
        "remediation": ("Manually verify each flagged misconfiguration "
                        "with a fresh test from a different network "
                        "vantage point. If the issue reproduces by hand, "
                        "treat as the corresponding CONFIRMED severity "
                        "tier (CRITICAL/HIGH/MEDIUM per attack class)."),
    }


# ── INFO rule: chain handoff visibility ──


def rule_chain_handoff(s):
    chain_next = s.get("chain_next") or []
    if not chain_next:
        return None
    return {
        "name":     "Cross-scanner chain handoff suggested",
        "severity": "INFO",
        "evidence": ("Confirmed OAuth misconfigurations enable downstream "
                     "scanners: " + ", ".join(chain_next)),
        "remediation": ("Re-run scan with chain_id propagation to "
                        "automatically follow up with: "
                        + ", ".join(chain_next)
                        + ". These will inherit the captured chain_id "
                        "via the VL-METHOD chaining engine."),
        "cwe": "CWE-1006",
    }


OAUTH_TOKEN_AUDIT_FINDING_RULES = [
    rule_no_oauth_discovered,
    rule_input_missing,
    rule_implicit_supported_warning,
    rule_pkce_not_supported,
    rule_clean_oauth_posture,
    rule_confirmed_open_redirect,
    rule_confirmed_missing_state,
    rule_confirmed_implicit_flow_live,
    rule_confirmed_pkce_not_enforced,
    rule_confirmed_refresh_not_rotated,
    rule_confirmed_scope_escalation,
    rule_suspected_oauth_misconfig,
    rule_chain_handoff,
]
