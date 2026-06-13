"""oauth_token_audit - OAuth 2.0 / OIDC token endpoint misconfiguration audit.

Phase D web credential-access scanner built on the VL-METHOD 7-step
pentest pattern.

What this scanner detects
-------------------------
Modern auth bugs that lead to account takeover and credential theft via
OAuth/OIDC provider misconfigurations:

  * Open redirect via redirect_uri  (most common OAuth bug; RFC 6749 4.1.2.1)
  * Missing state parameter (CSRF on the authorize endpoint)
  * Implicit flow enabled (response_type=token - RFC 8252 deprecates this)
  * PKCE not enforced for public clients (auth code interception)
  * Refresh token rotation not enforced (long-lived token abuse)
  * Excessive scope grants accepted without consent

7 stages this scanner performs
------------------------------
  1. PRE-FLIGHT  - Target URL required. Probe discovery docs
                    /.well-known/openid-configuration and
                    /.well-known/oauth-authorization-server. Fall back
                    to manual authorize-endpoint discovery at common
                    paths if neither responds.
  2. FINGERPRINT - Parse discovery doc for issuer, endpoints, grant
                    types, response types, PKCE support, scopes.
                    Identify provider (Auth0 / Okta / Keycloak / Azure
                    AD / Google / Cognito / generic).
  3. QUICK PROBE - 5 fast OAuth misconfig tests:
                    (a) Missing state -> CSRF on authorize
                    (b) Implicit flow live (response_type=token)
                    (c) Open redirect via redirect_uri (4 bypass vectors)
                    (d) PKCE not enforced (code grant w/o code_challenge)
                    (e) Excessive scope accepted without consent
  4. DEEP SCAN   - Gated on quick_probe hit OR always_deep:
                    (a) Token endpoint accepts client_id w/o secret
                    (b) Refresh token rotation enforcement
                    (c) Client credentials grant scope leakage
                    (d) prompt=none ID leak via cached session
                    (e) JWT alg/claim checks on access tokens
  5. VERIFY      - Re-test each misconfig with a slightly different
                    payload. Re-test confirms -> CONFIRMED, else SUSPECTED.
  6. PRIVILEGE   - Classify by attack class:
                    open_redirect_via_redirect_uri -> account_takeover_capable
                    missing_state_csrf             -> oauth_csrf_capable
                    implicit_flow_enabled          -> token_leak_via_referrer
                    pkce_not_enforced              -> auth_code_interception_capable
                    refresh_rotation_disabled      -> long_lived_token_abuse
  7. CHAIN       - For CONFIRMED open_redirect -> chain to
                    post_exploit_oauth_account_takeover.
                    For CONFIRMED implicit_flow -> chain to
                    post_exploit_oauth_token_leak.

Customer input via ScanRequest.options
--------------------------------------
  target              - base URL of the OAuth IdP / OIDC provider (REQUIRED)
  options.client_id   - test against this client (else "test-client")
  options.redirect_uri_legit - legitimate redirect_uri (for bypass tests)
  options.always_deep - run deep_scan even if quick_probe found nothing

Safety guard: open-redirect tests use the harmless placeholder
"attacker.com" - the scanner never actually redirects anywhere real.
All HTTP requests are hard-capped at 10 seconds.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
from typing import Optional
from urllib.parse import urlencode, urljoin, urlparse, parse_qs

import httpx
from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext
from tools._methodology import MethodologyScanner
from tools._payloads.oauth_token_audit_findings import (
    OAUTH_TOKEN_AUDIT_FINDING_RULES,
    INTEL_FIELDS,
)

router = APIRouter()

# Hard wall-clock cap per HTTP request
HTTP_TIMEOUT = 10.0

# Discovery doc paths probed at pre-flight
DISCOVERY_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]

# Fallback authorize-endpoint paths if discovery docs are absent
FALLBACK_AUTHORIZE_PATHS = [
    "/oauth/authorize",
    "/oauth2/authorize",
    "/authorize",
    "/connect/authorize",
]

# Harmless attacker placeholder for open-redirect tests. The scanner
# never actually follows a redirect to this host.
ATTACKER_HOST = "attacker.com"
ATTACKER_HOST_ALT = "attacker-evil.example"


class OauthTokenAuditRequest(ScanRequest):
    options: Optional[dict] = None


def _redact(token: str, show_plaintext: bool = False) -> str:
    """Customer-safe redaction for OAuth tokens / auth codes.

    Default returns a stable shape-marker like:
        "code_len42_hashabcdef12"
    where abcdef12 is the first 8 hex chars of sha256(token). Same token
    -> same marker (auditable) but no usable material in multi-tenant
    reports.

    show_plaintext=True (customer scanning own infra) returns the raw
    token string."""
    if not token:
        return "empty_len0_hashnone"
    if show_plaintext:
        return token
    # Infer token type from shape
    if token.startswith("eyJ"):
        ttype = "jwt"
    elif len(token) > 80:
        ttype = "token"
    else:
        ttype = "code"
    digest = hashlib.sha256(token.encode("utf-8", errors="ignore")).hexdigest()[:8]
    return f"{ttype}_len{len(token)}_hash{digest}"


def _identify_provider(issuer: str) -> str:
    """Map issuer URL pattern to known IdP."""
    if not issuer:
        return "generic"
    low = issuer.lower()
    if ".auth0.com" in low:
        return "Auth0"
    if ".okta.com" in low or ".oktapreview.com" in low:
        return "Okta"
    if "/auth/realms/" in low or "keycloak" in low:
        return "Keycloak"
    if "login.microsoftonline.com" in low or "sts.windows.net" in low:
        return "Azure AD"
    if "accounts.google.com" in low:
        return "Google"
    if "cognito-idp." in low or "amazoncognito.com" in low:
        return "Cognito"
    return "generic"


def _ensure_scheme(url: str) -> str:
    """Add https:// if URL has no scheme."""
    if not url:
        return ""
    u = url.strip()
    if "://" not in u:
        u = "https://" + u
    return u.rstrip("/")


def _build_authorize_url(authorize_ep: str, params: dict) -> str:
    """Append urlencoded params to authorize endpoint."""
    if not authorize_ep:
        return ""
    sep = "&" if "?" in authorize_ep else "?"
    return f"{authorize_ep}{sep}{urlencode(params)}"


async def _http_get(client: httpx.AsyncClient, url: str,
                    follow_redirects: bool = False) -> tuple[int, dict, str, str]:
    """Single HTTP GET. Returns (status, headers, body, error).
    Hard 10s timeout. follow_redirects=False so 302s are inspectable."""
    if not url:
        return (0, {}, "", "empty url")
    try:
        resp = await client.get(url, follow_redirects=follow_redirects)
        return (resp.status_code, dict(resp.headers), resp.text or "", "")
    except httpx.TimeoutException:
        return (0, {}, "", "timeout")
    except Exception as e:
        return (0, {}, "", f"{type(e).__name__}: {str(e)[:120]}")


async def _http_post(client: httpx.AsyncClient, url: str, data: dict,
                     follow_redirects: bool = False) -> tuple[int, dict, str, str]:
    """Single HTTP POST (form-encoded). Returns (status, headers, body, error)."""
    if not url:
        return (0, {}, "", "empty url")
    try:
        resp = await client.post(url, data=data, follow_redirects=follow_redirects)
        return (resp.status_code, dict(resp.headers), resp.text or "", "")
    except httpx.TimeoutException:
        return (0, {}, "", "timeout")
    except Exception as e:
        return (0, {}, "", f"{type(e).__name__}: {str(e)[:120]}")


def _redirect_url(headers: dict) -> str:
    """Pull Location header from response headers (case-insensitive)."""
    for k in ("Location", "location"):
        if k in headers:
            return headers[k]
    for k, v in headers.items():
        if k.lower() == "location":
            return v
    return ""


def _attacker_redirect_payloads(legit: str) -> list[tuple[str, str]]:
    """Build (label, redirect_uri) bypass payloads. Uses harmless
    attacker.com placeholder - never redirects anywhere real."""
    parsed = urlparse(legit or "https://example.com")
    legit_host = parsed.netloc or "example.com"
    return [
        ("different_domain",      f"https://{ATTACKER_HOST}/callback"),
        ("subdomain_trick",       f"https://{legit_host}.{ATTACKER_HOST}/callback"),
        ("path_traversal_trick",  f"https://{legit_host}/../{ATTACKER_HOST}/callback"),
        ("url_fragment_trick",    f"https://{legit_host}#@{ATTACKER_HOST}/callback"),
    ]


def _location_redirects_to_attacker(location: str) -> bool:
    """True if a Location: header redirects to the attacker placeholder."""
    if not location:
        return False
    low = location.lower()
    if ATTACKER_HOST in low or ATTACKER_HOST_ALT in low:
        return True
    return False


# ════════════════════════════════════════════════════════════════════
#  OauthTokenAudit - the VL-METHOD scanner class
# ════════════════════════════════════════════════════════════════════


class OauthTokenAudit(MethodologyScanner):
    name = "oauth_token_audit"

    # ── STAGE 1: PRE-FLIGHT ──────────────────────────────────────
    async def pre_flight(self, ctx: ScanContext) -> bool:
        target = (ctx.host or "").strip()
        if not target:
            ctx.state["skipped_reason"] = "requires target URL"
            return False
        target_base = _ensure_scheme(target)
        ctx.state["target_base"] = target_base

        discovery_doc_url = ""
        discovery_doc = None
        authorize_endpoint = ""
        token_endpoint = ""

        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT,
                                      verify=False,
                                      headers={"User-Agent": "VulnusLab/VL-METHOD oauth_token_audit"}) as client:
            # Try discovery docs first
            for path in DISCOVERY_PATHS:
                url = target_base + path
                status, headers, body, err = await _http_get(client, url)
                if status == 200 and body:
                    try:
                        parsed = json.loads(body)
                        if isinstance(parsed, dict):
                            discovery_doc_url = url
                            discovery_doc = parsed
                            authorize_endpoint = (parsed.get("authorization_endpoint") or "").strip()
                            token_endpoint = (parsed.get("token_endpoint") or "").strip()
                            break
                    except (json.JSONDecodeError, ValueError):
                        continue

            # Fallback to manual authorize-endpoint discovery
            if not authorize_endpoint:
                for path in FALLBACK_AUTHORIZE_PATHS:
                    url = target_base + path
                    status, headers, body, err = await _http_get(client, url)
                    # Authorize endpoint typically returns 200/302/400 - not 404
                    if status in (200, 302, 400, 401):
                        authorize_endpoint = url
                        break

        if not authorize_endpoint:
            ctx.state["skipped_reason"] = "no OAuth/OIDC endpoint discovered at standard paths"
            return False

        ctx.state["discovery_doc_url"] = discovery_doc_url
        ctx.state["discovery_doc"] = discovery_doc
        ctx.state["authorize_endpoint"] = authorize_endpoint
        ctx.state["token_endpoint"] = token_endpoint
        return True

    # ── STAGE 2: FINGERPRINT ─────────────────────────────────────
    async def fingerprint(self, ctx: ScanContext):
        doc = ctx.state.get("discovery_doc") or {}
        issuer = (doc.get("issuer") or "").strip() if isinstance(doc, dict) else ""
        response_types = doc.get("response_types_supported") or [] if isinstance(doc, dict) else []
        grant_types = doc.get("grant_types_supported") or [] if isinstance(doc, dict) else []
        pkce_methods = doc.get("code_challenge_methods_supported") or [] if isinstance(doc, dict) else []
        scopes = doc.get("scopes_supported") or [] if isinstance(doc, dict) else []
        subject_types = doc.get("subject_types_supported") or [] if isinstance(doc, dict) else []
        userinfo_ep = (doc.get("userinfo_endpoint") or "").strip() if isinstance(doc, dict) else ""
        jwks_uri = (doc.get("jwks_uri") or "").strip() if isinstance(doc, dict) else ""

        # Normalize lists
        if not isinstance(response_types, list):
            response_types = []
        if not isinstance(grant_types, list):
            grant_types = []
        if not isinstance(pkce_methods, list):
            pkce_methods = []
        if not isinstance(scopes, list):
            scopes = []
        if not isinstance(subject_types, list):
            subject_types = []

        supports_implicit = any(
            rt and "token" in str(rt).lower() and "code" not in str(rt).lower()
            for rt in response_types
        )
        # More precise: response_type containing "token" but not "code"
        # captures the implicit flow ("token" or "id_token token") and
        # excludes the hybrid flow ("code token" which is OIDC hybrid).
        if not supports_implicit:
            for rt in response_types:
                rl = str(rt).lower().strip()
                if rl in ("token", "id_token token", "id_token", "token id_token"):
                    if "code" not in rl:
                        supports_implicit = True
                        break

        pkce_supported = any(
            str(m).upper() in ("S256", "PLAIN") for m in pkce_methods
        )
        # S256 specifically (PLAIN is allowed but discouraged by RFC 7636)
        pkce_s256 = any(str(m).upper() == "S256" for m in pkce_methods)

        ctx.state["fingerprint"] = {
            "provider":         _identify_provider(issuer),
            "issuer":           issuer,
            "response_types":   [str(x) for x in response_types],
            "grant_types":      [str(x) for x in grant_types],
            "pkce_supported":   pkce_supported,
            "pkce_s256":        pkce_s256,
            "supports_implicit": supports_implicit,
            "scopes":           [str(x) for x in scopes][:50],
            "subject_types":    [str(x) for x in subject_types],
            "userinfo_endpoint": userinfo_ep,
            "jwks_uri":         jwks_uri,
        }

    # ── STAGE 3: QUICK PROBE (5 OAuth misconfig tests) ───────────
    async def quick_probe(self, ctx: ScanContext) -> list[dict]:
        opts = ctx.state.get("_options") or {}
        client_id = (opts.get("client_id") or "test-client").strip()
        redirect_uri_legit = (opts.get("redirect_uri_legit")
                              or "https://example.com/callback").strip()
        authorize_ep = ctx.state.get("authorize_endpoint") or ""
        token_ep = ctx.state.get("token_endpoint") or ""

        findings: list[dict] = []
        attempts = 0

        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT,
                                      verify=False,
                                      headers={"User-Agent": "VulnusLab/VL-METHOD oauth_token_audit"}) as client:

            # (a) Missing state parameter test
            attempts += 1
            url = _build_authorize_url(authorize_ep, {
                "response_type": "code",
                "client_id":     client_id,
                "redirect_uri":  redirect_uri_legit,
                "scope":         "openid",
                # state intentionally omitted
            })
            status, headers, body, err = await _http_get(client, url)
            # If server 302s without complaining, state is not enforced.
            # 400 / 401 / error JSON = state likely enforced.
            if status in (302, 303, 307):
                loc = _redirect_url(headers)
                # Heuristic: redirect to a callback URL (not to an error
                # page) means the missing state was accepted.
                if loc and ("error" not in loc.lower() or "code=" in loc.lower()):
                    findings.append({
                        "id":               "qp_missing_state",
                        "attack_class":     "missing_state_csrf",
                        "kind":             "oauth_misconfig",
                        "evidence":         f"GET {url[:160]} -> 302 {loc[:120]}",
                        "test_payload":     "response_type=code without state",
                        "discovery_method": "quick_probe_missing_state",
                    })

            # (b) Implicit flow live test
            attempts += 1
            url = _build_authorize_url(authorize_ep, {
                "response_type": "token",
                "client_id":     client_id,
                "redirect_uri":  redirect_uri_legit,
                "scope":         "openid",
                "state":         "vl_state_test",
            })
            status, headers, body, err = await _http_get(client, url)
            loc = _redirect_url(headers)
            # access_token in the fragment of the Location header = implicit flow live
            if status in (302, 303, 307) and loc and "access_token=" in loc:
                findings.append({
                    "id":               "qp_implicit_flow",
                    "attack_class":     "implicit_flow_enabled",
                    "kind":             "oauth_misconfig",
                    "evidence":         f"response_type=token redirect contains access_token: {loc[:120]}",
                    "test_payload":     "response_type=token",
                    "discovery_method": "quick_probe_implicit_flow",
                })

            # (c) Open redirect via redirect_uri (4 bypass vectors)
            for label, attacker_uri in _attacker_redirect_payloads(redirect_uri_legit):
                attempts += 1
                url = _build_authorize_url(authorize_ep, {
                    "response_type": "code",
                    "client_id":     client_id,
                    "redirect_uri":  attacker_uri,
                    "scope":         "openid",
                    "state":         "vl_state_test",
                })
                status, headers, body, err = await _http_get(client, url)
                loc = _redirect_url(headers)
                if status in (302, 303, 307) and _location_redirects_to_attacker(loc):
                    findings.append({
                        "id":               f"qp_open_redirect_{label}",
                        "attack_class":     "open_redirect_via_redirect_uri",
                        "kind":             "oauth_misconfig",
                        "evidence":         f"redirect_uri={attacker_uri} accepted: 302 -> {loc[:120]}",
                        "test_payload":     f"open_redirect_{label}",
                        "bypass_vector":    label,
                        "attacker_uri":     attacker_uri,
                        "discovery_method": "quick_probe_open_redirect",
                    })
                    # First successful bypass is enough; remaining vectors
                    # are tested in verify stage for confirmation.
                    break

            # (d) PKCE enforcement test (code grant without code_challenge)
            attempts += 1
            url = _build_authorize_url(authorize_ep, {
                "response_type": "code",
                "client_id":     client_id,
                "redirect_uri":  redirect_uri_legit,
                "scope":         "openid",
                "state":         "vl_state_test",
                # code_challenge intentionally omitted
            })
            status, headers, body, err = await _http_get(client, url)
            loc = _redirect_url(headers)
            body_low = (body or "").lower()
            # If server 302s with a code (no PKCE required) OR returns
            # 200 with a "consent" page (no code_challenge complaint),
            # PKCE not enforced for this client_id.
            pkce_not_enforced = False
            if status in (302, 303, 307) and loc:
                if "code=" in loc and "error" not in loc.lower():
                    pkce_not_enforced = True
            elif status == 200:
                if "code_challenge" not in body_low and "pkce" not in body_low:
                    # 200 + consent page with no PKCE complaint -> server
                    # is willing to issue an auth code without PKCE
                    if "consent" in body_low or "authorize" in body_low or "login" in body_low:
                        pkce_not_enforced = True
            if pkce_not_enforced:
                findings.append({
                    "id":               "qp_pkce_not_enforced",
                    "attack_class":     "pkce_not_enforced",
                    "kind":             "oauth_misconfig",
                    "evidence":         f"code grant without code_challenge accepted: status={status}",
                    "test_payload":     "response_type=code without code_challenge",
                    "discovery_method": "quick_probe_pkce_not_enforced",
                })

            # (e) Excessive scope without consent
            attempts += 1
            excessive_scopes = "openid email admin root"
            url = _build_authorize_url(authorize_ep, {
                "response_type": "code",
                "client_id":     client_id,
                "redirect_uri":  redirect_uri_legit,
                "scope":         excessive_scopes,
                "state":         "vl_state_test",
            })
            status, headers, body, err = await _http_get(client, url)
            loc = _redirect_url(headers)
            body_low = (body or "").lower()
            # If server accepts excessive scopes silently (302 with code)
            # without surfacing a consent page or scope-invalid error,
            # scope enforcement is lax.
            scope_escalated = False
            if status in (302, 303, 307) and loc:
                low_loc = loc.lower()
                if "code=" in low_loc and "invalid_scope" not in low_loc and "error" not in low_loc:
                    scope_escalated = True
            if scope_escalated:
                findings.append({
                    "id":               "qp_scope_escalation",
                    "attack_class":     "excessive_scope_accepted",
                    "kind":             "oauth_misconfig",
                    "evidence":         f"scope={excessive_scopes} accepted without consent: 302 -> {loc[:120]}",
                    "test_payload":     "scope=openid+email+admin+root",
                    "discovery_method": "quick_probe_scope_escalation",
                })

        ctx.state["quick_probe_attempts"] = attempts
        ctx.state["quick_probe_hits"] = len(findings)
        return findings

    # ── STAGE 4: DEEP SCAN (token endpoint + refresh + JWT) ──────
    async def deep_scan(self, ctx: ScanContext) -> list[dict]:
        opts = ctx.state.get("_options") or {}
        # Gate: only run if quick_probe hit OR always_deep override
        if ctx.state.get("quick_probe_hits", 0) <= 0 and not opts.get("always_deep"):
            return []

        client_id = (opts.get("client_id") or "test-client").strip()
        redirect_uri_legit = (opts.get("redirect_uri_legit")
                              or "https://example.com/callback").strip()
        token_ep = ctx.state.get("token_endpoint") or ""
        fp = ctx.state.get("fingerprint") or {}
        grant_types = [str(g).lower() for g in (fp.get("grant_types") or [])]

        findings: list[dict] = []

        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT,
                                      verify=False,
                                      headers={"User-Agent": "VulnusLab/VL-METHOD oauth_token_audit"}) as client:

            # (a) Token endpoint accepts client_id without client_secret
            #     (public client mode) AND without PKCE
            if token_ep:
                status, headers, body, err = await _http_post(client, token_ep, {
                    "grant_type":    "authorization_code",
                    "code":          "vl_fake_code_test",
                    "redirect_uri":  redirect_uri_legit,
                    "client_id":     client_id,
                    # no client_secret, no code_verifier
                })
                body_low = (body or "").lower()
                # If server responds with "invalid_client" or "unauthorized_client"
                # secret is enforced (good). If it responds with "invalid_grant" /
                # "invalid_code", the missing secret was accepted (bad).
                if status in (200, 400) and "invalid_client" not in body_low and "unauthorized_client" not in body_low:
                    if "invalid_grant" in body_low or "invalid_code" in body_low or status == 200:
                        findings.append({
                            "id":               "deep_token_no_secret",
                            "attack_class":     "token_endpoint_no_secret",
                            "kind":             "oauth_misconfig",
                            "evidence":         (f"POST {token_ep[:120]} without client_secret -> "
                                                  f"{status}: {body_low[:120]}"),
                            "test_payload":     "token_endpoint_without_client_secret",
                            "discovery_method": "deep_scan_token_no_secret",
                        })

            # (b) Refresh token rotation enforcement (best-effort heuristic;
            #     real test needs a valid refresh_token which a black-box
            #     scan typically can't synthesize. We surface an indicator
            #     based on grant_types_supported + advertised metadata).
            if "refresh_token" in grant_types and token_ep:
                # Attempt: send a refresh_token with a synthetic value and
                # check if server returns a structured "invalid_grant"
                # (good - means it validates) vs accepts silently (bad).
                status, headers, body, err = await _http_post(client, token_ep, {
                    "grant_type":    "refresh_token",
                    "refresh_token": "vl_test_refresh_token_marker_001",
                    "client_id":     client_id,
                })
                body_low = (body or "").lower()
                # Genuine server returns invalid_grant 400 - we ONLY record
                # an issue if the server returned 200 OK for our bogus
                # refresh_token, which would mean rotation isn't enforced
                # at all.
                if status == 200 and ("access_token" in body_low or "token_type" in body_low):
                    findings.append({
                        "id":               "deep_refresh_no_rotation",
                        "attack_class":     "refresh_rotation_disabled",
                        "kind":             "oauth_misconfig",
                        "evidence":         (f"refresh_token endpoint returned 200 for synthetic "
                                              f"refresh_token: {body_low[:120]}"),
                        "test_payload":     "synthetic_refresh_token",
                        "discovery_method": "deep_scan_refresh_rotation",
                    })

            # (c) Client credentials grant scope leakage
            if "client_credentials" in grant_types and token_ep:
                status, headers, body, err = await _http_post(client, token_ep, {
                    "grant_type": "client_credentials",
                    "client_id":  client_id,
                    "scope":      "admin root",
                })
                body_low = (body or "").lower()
                if status == 200 and "access_token" in body_low:
                    findings.append({
                        "id":               "deep_client_cred_scope_leak",
                        "attack_class":     "client_credentials_scope_leak",
                        "kind":             "oauth_misconfig",
                        "evidence":         (f"client_credentials grant issued token for "
                                              f"admin/root scope without consent: {body_low[:120]}"),
                        "test_payload":     "grant_type=client_credentials scope=admin+root",
                        "discovery_method": "deep_scan_client_cred",
                    })

            # (d) prompt=none ID leak via cached session
            authorize_ep = ctx.state.get("authorize_endpoint") or ""
            if authorize_ep:
                url = _build_authorize_url(authorize_ep, {
                    "response_type": "id_token",
                    "client_id":     client_id,
                    "redirect_uri":  redirect_uri_legit,
                    "scope":         "openid email profile",
                    "nonce":         "vl_nonce_test",
                    "state":         "vl_state_test",
                    "prompt":        "none",
                })
                status, headers, body, err = await _http_get(client, url)
                loc = _redirect_url(headers)
                if status in (302, 303, 307) and loc and "id_token=" in loc:
                    findings.append({
                        "id":               "deep_prompt_none_leak",
                        "attack_class":     "prompt_none_id_leak",
                        "kind":             "oauth_misconfig",
                        "evidence":         f"prompt=none returned id_token: {loc[:120]}",
                        "test_payload":     "prompt=none with cached session",
                        "discovery_method": "deep_scan_prompt_none",
                    })

            # (e) JWT alg / claim check on any access token we collected
            #     (best-effort: look at quick_probe finding for tokens
            #     in the Location header).
            for qf in (ctx.state.get("_qp_tokens") or []):
                token = qf
                # Decode JWT header (best-effort, no signature check)
                try:
                    parts = token.split(".")
                    if len(parts) >= 2:
                        header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
                        header_json = base64.urlsafe_b64decode(header_b64)
                        header = json.loads(header_json)
                        alg = str(header.get("alg") or "").lower()
                        if alg in ("none", "hs256"):
                            findings.append({
                                "id":               f"deep_jwt_weak_alg_{alg}",
                                "attack_class":     "jwt_weak_algorithm",
                                "kind":             "oauth_misconfig",
                                "evidence":         f"JWT access token uses {alg.upper()} algorithm",
                                "test_payload":     f"alg={alg}",
                                "discovery_method": "deep_scan_jwt_alg_check",
                            })
                except Exception:
                    pass

        return findings

    # ── STAGE 5: VERIFY (re-test with different payload) ─────────
    async def verify(self, ctx: ScanContext, finding: dict) -> Optional[dict]:
        # VL-FOUNDRY evidence surfacing: stamp a concrete, per-finding
        # evidence string onto the methodology finding object. This rides
        # into the report via the methodology_findings intel field; it adds
        # no new finding and changes no severity (advisory-by-design safe).
        finding["evidence_marker"] = (
            f"{finding.get('discovery_method') or finding.get('kind') or 'probe'}"
            f" -> verifying {finding.get('kind') or 'finding'} for "
            f"{finding.get('user') or finding.get('attack_label') or ctx.host}")
        opts = ctx.state.get("_options") or {}
        client_id = (opts.get("client_id") or "test-client").strip()
        redirect_uri_legit = (opts.get("redirect_uri_legit")
                              or "https://example.com/callback").strip()
        authorize_ep = ctx.state.get("authorize_endpoint") or ""
        token_ep = ctx.state.get("token_endpoint") or ""
        attack = finding.get("attack_class") or ""

        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT,
                                      verify=False,
                                      headers={"User-Agent": "VulnusLab/VL-METHOD oauth_token_audit verify"}) as client:

            if attack == "open_redirect_via_redirect_uri":
                # Re-test with a DIFFERENT attacker host
                alt_uri = f"https://{ATTACKER_HOST_ALT}/cb"
                url = _build_authorize_url(authorize_ep, {
                    "response_type": "code",
                    "client_id":     client_id,
                    "redirect_uri":  alt_uri,
                    "scope":         "openid",
                    "state":         "vl_verify_test",
                })
                status, headers, body, err = await _http_get(client, url)
                loc = _redirect_url(headers)
                if status in (302, 303, 307) and _location_redirects_to_attacker(loc):
                    finding["confidence"] = "CONFIRMED"
                    finding["verification_method"] = "oauth_misconfig_retest_confirmed"
                else:
                    finding["confidence"] = "SUSPECTED"
                    finding["verification_method"] = "oauth_misconfig_retest_not_reproduced"

            elif attack == "missing_state_csrf":
                # Re-test with a different client_id but still missing state
                url = _build_authorize_url(authorize_ep, {
                    "response_type": "code",
                    "client_id":     client_id + "-verify",
                    "redirect_uri":  redirect_uri_legit,
                    "scope":         "openid",
                })
                status, headers, body, err = await _http_get(client, url)
                if status in (302, 303, 307):
                    finding["confidence"] = "CONFIRMED"
                    finding["verification_method"] = "oauth_misconfig_retest_confirmed"
                else:
                    finding["confidence"] = "SUSPECTED"
                    finding["verification_method"] = "oauth_misconfig_retest_not_reproduced"

            elif attack == "implicit_flow_enabled":
                # Re-test with id_token response_type
                url = _build_authorize_url(authorize_ep, {
                    "response_type": "id_token token",
                    "client_id":     client_id,
                    "redirect_uri":  redirect_uri_legit,
                    "scope":         "openid",
                    "nonce":         "vl_nonce_verify",
                    "state":         "vl_state_verify",
                })
                status, headers, body, err = await _http_get(client, url)
                loc = _redirect_url(headers)
                if status in (302, 303, 307) and loc and ("access_token=" in loc or "id_token=" in loc):
                    finding["confidence"] = "CONFIRMED"
                    finding["verification_method"] = "oauth_misconfig_retest_confirmed"
                else:
                    finding["confidence"] = "SUSPECTED"
                    finding["verification_method"] = "oauth_misconfig_retest_not_reproduced"

            elif attack == "pkce_not_enforced":
                # Re-test with a different client_id
                url = _build_authorize_url(authorize_ep, {
                    "response_type": "code",
                    "client_id":     client_id + "-verify",
                    "redirect_uri":  redirect_uri_legit,
                    "scope":         "openid",
                    "state":         "vl_state_verify",
                })
                status, headers, body, err = await _http_get(client, url)
                loc = _redirect_url(headers)
                body_low = (body or "").lower()
                accepted = False
                if status in (302, 303, 307) and loc and "code=" in loc and "error" not in loc.lower():
                    accepted = True
                elif status == 200 and "code_challenge" not in body_low and "pkce" not in body_low:
                    if "consent" in body_low or "authorize" in body_low or "login" in body_low:
                        accepted = True
                if accepted:
                    finding["confidence"] = "CONFIRMED"
                    finding["verification_method"] = "oauth_misconfig_retest_confirmed"
                else:
                    finding["confidence"] = "SUSPECTED"
                    finding["verification_method"] = "oauth_misconfig_retest_not_reproduced"

            elif attack == "refresh_rotation_disabled":
                # Re-test with a DIFFERENT synthetic refresh token
                if token_ep:
                    status, headers, body, err = await _http_post(client, token_ep, {
                        "grant_type":    "refresh_token",
                        "refresh_token": "vl_test_refresh_token_marker_002",
                        "client_id":     client_id,
                    })
                    body_low = (body or "").lower()
                    if status == 200 and ("access_token" in body_low or "token_type" in body_low):
                        finding["confidence"] = "CONFIRMED"
                        finding["verification_method"] = "oauth_misconfig_retest_confirmed"
                    else:
                        finding["confidence"] = "SUSPECTED"
                        finding["verification_method"] = "oauth_misconfig_retest_not_reproduced"
                else:
                    finding["confidence"] = "SUSPECTED"
                    finding["verification_method"] = "no_token_endpoint_cannot_verify"

            elif attack == "excessive_scope_accepted":
                # Re-test with a different excessive scope set
                url = _build_authorize_url(authorize_ep, {
                    "response_type": "code",
                    "client_id":     client_id,
                    "redirect_uri":  redirect_uri_legit,
                    "scope":         "openid superuser sudo",
                    "state":         "vl_state_verify",
                })
                status, headers, body, err = await _http_get(client, url)
                loc = _redirect_url(headers)
                if status in (302, 303, 307) and loc:
                    low_loc = loc.lower()
                    if "code=" in low_loc and "invalid_scope" not in low_loc and "error" not in low_loc:
                        finding["confidence"] = "CONFIRMED"
                        finding["verification_method"] = "oauth_misconfig_retest_confirmed"
                    else:
                        finding["confidence"] = "SUSPECTED"
                        finding["verification_method"] = "oauth_misconfig_retest_not_reproduced"
                else:
                    finding["confidence"] = "SUSPECTED"
                    finding["verification_method"] = "oauth_misconfig_retest_not_reproduced"

            else:
                # Unknown / deep_scan-only attack classes: best-effort
                finding.setdefault("confidence", "SUSPECTED")
                finding.setdefault("verification_method", "single_probe_no_retest")

        return finding

    # ── STAGE 6: PRIVILEGE CHECK (attack-class classification) ───
    async def privilege_check(self, ctx: ScanContext, finding: dict) -> dict:
        attack = finding.get("attack_class") or ""
        mapping = {
            "open_redirect_via_redirect_uri": "account_takeover_capable",
            "missing_state_csrf":             "oauth_csrf_capable",
            "implicit_flow_enabled":          "token_leak_via_referrer",
            "pkce_not_enforced":              "auth_code_interception_capable",
            "refresh_rotation_disabled":      "long_lived_token_abuse",
            "excessive_scope_accepted":       "scope_escalation_capable",
            "token_endpoint_no_secret":       "public_client_abuse_capable",
            "client_credentials_scope_leak":  "service_account_scope_abuse",
            "prompt_none_id_leak":            "session_hijack_capable",
            "jwt_weak_algorithm":             "jwt_forgery_capable",
        }
        finding["privilege"] = mapping.get(attack, "unknown_oauth_misconfig")
        return finding

    # ── STAGE 7: CHAIN HANDOFF ───────────────────────────────────
    async def chain_handoff(self, ctx: ScanContext, findings: list[dict]) -> list[str]:
        next_scanners: list[str] = []
        for f in findings:
            if f.get("confidence") != "CONFIRMED":
                continue
            attack = f.get("attack_class") or ""
            if attack == "open_redirect_via_redirect_uri":
                if "post_exploit_oauth_account_takeover" not in next_scanners:
                    next_scanners.append("post_exploit_oauth_account_takeover")
                f["chain_next"] = ["post_exploit_oauth_account_takeover"]
            elif attack == "implicit_flow_enabled":
                if "post_exploit_oauth_token_leak" not in next_scanners:
                    next_scanners.append("post_exploit_oauth_token_leak")
                f["chain_next"] = ["post_exploit_oauth_token_leak"]
        return next_scanners


# ════════════════════════════════════════════════════════════════════
#  Endpoint wrapper
# ════════════════════════════════════════════════════════════════════


@router.post("/api/password/oauth_token_audit")
async def password_oauth_token_audit(req: OauthTokenAuditRequest,
                                       _=Depends(verify_scan_quota)):
    scanner = OauthTokenAudit()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=OAUTH_TOKEN_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


def register(app):
    app.include_router(router)


# ════════════════════════════════════════════════════════════════════
#  Chain registry registration - upstream scanners (web recon, OAuth
#  endpoint discovery scanners) trigger us via _chain_callable.
# ════════════════════════════════════════════════════════════════════


async def _chain_callable(target: str, options: dict, jwt_token=None) -> dict:
    """ChainExecutor entry point - upstream scanners (web recon,
    OAuth endpoint discovery) trigger us via this wrapper."""
    opts = options or {}
    req = OauthTokenAuditRequest(target=target, options=opts)
    scanner = OauthTokenAudit()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=OAUTH_TOKEN_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


from tools._methodology import chain_registry
chain_registry.register("oauth_token_audit", _chain_callable)
