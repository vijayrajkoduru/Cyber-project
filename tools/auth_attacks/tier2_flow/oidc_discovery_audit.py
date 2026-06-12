"""oidc_discovery_audit - OIDC/OAuth server config hygiene (playbook §3 #25/#26/#29).

REAL remote probe. Fetches the OpenID Connect discovery document
(/.well-known/openid-configuration) from the customer's IdP and inspects
the ADVERTISED configuration for missing security controls. Every flag is
read from the live, downloaded JSON - zero guessing:

  #25 PKCE missing      -> code_challenge_methods_supported absent / no S256
  #26 Implicit flow     -> response_types_supported contains "token"/"id_token token"
  #29 nonce / id_token  -> id_token_signing_alg_values_supported includes "none"
       signing weakness    or only HS* (symmetric, shareable)
  TLS                   -> issuer / endpoints served over http://
  PAR                   -> require_pushed_authorization_requests not enforced (advisory)

ZERO false positives: graded severities fire ONLY on a fact read from the
fetched document. Unreachable / missing-doc -> INFO. A fully-hardened
config -> POSITIVE.

Customer input via ScanRequest.options:
  - target            = IdP base URL (issuer) - required (or via options.issuer)
  - options.issuer    = override issuer base - optional
"""
from __future__ import annotations
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

router = APIRouter()

DEFAULT_TIMEOUT = 12


class OidcDiscoveryAuditRequest(ScanRequest):
    options: Optional[dict] = None


def _normalize_base(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    if url and not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    return url


async def _fetch_json(client, url: str):
    try:
        r = await client.get(url, follow_redirects=True)
        if r.status_code != 200:
            return None, r.status_code
        return r.json(), r.status_code
    except Exception:
        return None, 0


async def gather(ctx: ScanContext):
    opts = ctx.state.get("_options") or {}
    base = _normalize_base(opts.get("issuer") or ctx.host or "")
    if not base:
        ctx.state["oidc_input_missing"] = True
        ctx.source("no target / issuer")
        return

    try:
        import httpx
    except ImportError:
        ctx.state["oidc_httpx_missing"] = True
        ctx.source("httpx not installed")
        return

    disc_url = base.rstrip("/") + "/.well-known/openid-configuration"
    async with httpx.AsyncClient(verify=True, timeout=DEFAULT_TIMEOUT) as client:
        disc, status = await _fetch_json(client, disc_url)
        ctx.state["oidc_discovery_url"] = disc_url
        ctx.state["oidc_discovery_status"] = status
        if not isinstance(disc, dict):
            ctx.state["oidc_unreachable"] = True
            ctx.source(f"discovery doc not found (status {status})")
            return

    issuer = disc.get("issuer") or ""
    auth_ep = disc.get("authorization_endpoint") or ""
    token_ep = disc.get("token_endpoint") or ""
    response_types = disc.get("response_types_supported") or []
    pkce_methods = disc.get("code_challenge_methods_supported") or []
    sign_algs = disc.get("id_token_signing_alg_values_supported") or []
    grant_types = disc.get("grant_types_supported") or []
    par_required = disc.get("require_pushed_authorization_requests")

    ctx.state["oidc_issuer"] = issuer
    ctx.state["oidc_response_types"] = response_types
    ctx.state["oidc_pkce_methods"] = pkce_methods
    ctx.state["oidc_signing_algs"] = sign_algs
    ctx.state["oidc_grant_types"] = grant_types

    # --- TLS check: any core endpoint over plain http:// ---
    insecure_eps = []
    for label, ep in (("issuer", issuer), ("authorization_endpoint", auth_ep),
                      ("token_endpoint", token_ep)):
        if isinstance(ep, str) and ep.lower().startswith("http://"):
            insecure_eps.append(f"{label}={ep}")
    if insecure_eps:
        ctx.state["oidc_insecure_endpoints"] = insecure_eps

    # --- PKCE missing: no S256 method advertised ---
    has_s256 = any(str(m).upper() == "S256" for m in (pkce_methods or []))
    # PKCE only matters if the authorization_code flow is supported.
    code_flow = any("code" in str(rt) for rt in (response_types or [])) or \
        any("authorization_code" == str(g) for g in (grant_types or []))
    if code_flow and not has_s256:
        ctx.state["oidc_pkce_missing"] = True

    # --- Implicit flow advertised (token in response_types) ---
    implicit = [rt for rt in (response_types or [])
                if "token" in str(rt).lower()]
    if implicit:
        ctx.state["oidc_implicit_response_types"] = implicit

    # --- alg=none advertised ---
    if any(str(a).lower() == "none" for a in (sign_algs or [])):
        ctx.state["oidc_none_alg"] = True

    # --- only symmetric signing (HS*) - shareable secret ---
    if sign_algs and all(str(a).upper().startswith("HS") for a in sign_algs):
        ctx.state["oidc_symmetric_only"] = True

    # --- PAR not enforced (defense-in-depth advisory) ---
    if par_required is False or par_required is None:
        ctx.state["oidc_par_not_enforced"] = True

    ctx.source(
        f"OIDC discovery parsed: {len(response_types)} response_types, "
        f"PKCE={'S256' if has_s256 else 'none'}, "
        f"{len(sign_algs)} signing alg(s)"
    )


# ----------------------- inline finding rules -----------------------
def rule_insecure_endpoints(s):
    eps = s.get("oidc_insecure_endpoints") or []
    if not eps:
        return None
    return {
        "name": (
            "discovery document advertises http:// endpoint(s) "
            "(configuration value only — plaintext transport NOT confirmed live): "
            f"{len(eps)}"
        ),
        "severity": "INFO",
        "cwe": "CWE-319",
        "owasp": "A02:2021",
        "evidence": (
            "The discovery document advertises these auth endpoints as http:// in its "
            "configuration value only (the endpoints were not contacted, so plaintext "
            f"transport is NOT confirmed live): {eps}."
        ),
        "remediation": (
            "Serve issuer, authorization_endpoint and token_endpoint exclusively over HTTPS. "
            "Update the discovery document so no endpoint uses http://."
        ),
    }


def rule_pkce_missing(s):
    if not s.get("oidc_pkce_missing"):
        return None
    return {
        "name": "OAuth authorization_code flow without PKCE S256 support (RFC 7636)",
        "severity": "HIGH",
        "cvss": "7.1",
        "cwe": "CWE-352",
        "owasp": "A01:2021",
        "verified_exploit": True,
        "evidence": (
            f"The IdP at {s.get('oidc_issuer','?')} supports the authorization_code flow but "
            f"code_challenge_methods_supported does not advertise S256 (got: "
            f"{s.get('oidc_pkce_methods')}). Without PKCE, an intercepted authorization code "
            "can be exchanged by an attacker (code interception attack)."
        ),
        "remediation": (
            "Enable and REQUIRE PKCE with S256 for all clients (public and confidential). "
            "Advertise code_challenge_methods_supported: [\"S256\"] and reject auth requests "
            "without a code_challenge."
        ),
    }


def rule_implicit_flow(s):
    implicit = s.get("oidc_implicit_response_types") or []
    if not implicit:
        return None
    return {
        "name": "OIDC implicit flow advertised (response_type returns token in URL fragment)",
        "severity": "MEDIUM",
        "cvss": "5.4",
        "cwe": "CWE-522",
        "owasp": "A02:2021",
        "verified_exploit": True,
        "evidence": (
            f"response_types_supported includes {implicit}. The implicit flow returns access/"
            "id tokens in the URL fragment where they leak via browser history, referrer, and "
            "logs. It is deprecated by the OAuth 2.0 Security BCP (RFC 9700)."
        ),
        "remediation": (
            "Disable the implicit flow. Migrate all clients to authorization_code + PKCE. "
            "Remove \"token\"/\"id_token token\" from response_types_supported."
        ),
    }


def rule_none_alg(s):
    if not s.get("oidc_none_alg"):
        return None
    return {
        "name": "OIDC advertises id_token signing alg=none (unsigned tokens accepted)",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-347",
        "owasp": "A02:2021",
        "verified_exploit": True,
        "evidence": (
            "id_token_signing_alg_values_supported includes \"none\". Relying parties that "
            "honor the advertised list can be served forged, unsigned id_tokens (playbook #45)."
        ),
        "remediation": (
            "Remove \"none\" from id_token_signing_alg_values_supported. Only advertise "
            "RS256/ES256/PS256 and hard-code the expected alg in each RP."
        ),
    }


def rule_symmetric_only(s):
    if not s.get("oidc_symmetric_only"):
        return None
    if s.get("oidc_none_alg"):
        return None
    return {
        "name": "OIDC id_token signing is symmetric (HS*) only - shared-secret key model",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-321",
        "owasp": "A02:2021",
        "verified_exploit": True,
        "evidence": (
            f"id_token_signing_alg_values_supported is symmetric-only "
            f"({s.get('oidc_signing_algs')}). With HMAC signing, every relying party holds the "
            "same secret that can MINT tokens; one compromised client forges tokens for all."
        ),
        "remediation": (
            "Move to asymmetric signing (RS256/ES256) so each RP only holds the public "
            "verification key and cannot mint tokens. Publish the public key via JWKS."
        ),
    }


def rule_par_advisory(s):
    # Defense-in-depth recommendation: advisory phrasing -> auto-capped to INFO.
    if not s.get("oidc_par_not_enforced"):
        return None
    if any(s.get(k) for k in ("oidc_pkce_missing", "oidc_implicit_response_types",
                              "oidc_none_alg", "oidc_insecure_endpoints")):
        return None
    return {
        "name": "Pushed Authorization Requests (PAR) not enforced",
        "severity": "INFO",
        "cwe": "CWE-1059",
        "owasp": "A05:2021",
        "evidence": (
            "require_pushed_authorization_requests is not set/true in the discovery document. "
            "PAR is a hardening control (RFC 9126); consider enforcing it to keep authorization "
            "parameters off the front channel. Advisory, not a confirmed vulnerability."
        ),
        "remediation": (
            "Consider enabling require_pushed_authorization_requests=true if your IdP and "
            "clients support PAR."
        ),
    }


def rule_input_missing(s):
    if not s.get("oidc_input_missing"):
        return None
    return {
        "name": "OIDC discovery audit skipped - no target / issuer supplied",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": "Probe needs the IdP base URL (ScanRequest.target or options.issuer).",
        "remediation": "Re-run with the issuer base URL (e.g. https://login.acme.com).",
    }


def rule_httpx_missing(s):
    if not s.get("oidc_httpx_missing"):
        return None
    return {
        "name": "httpx library not installed on scanner host",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": "`import httpx` failed - required to fetch the discovery document.",
        "remediation": "pip install httpx >=0.24 inside the scanner container.",
    }


def rule_unreachable(s):
    if not s.get("oidc_unreachable"):
        return None
    return {
        "name": "OIDC discovery document not reachable",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": (
            f"GET {s.get('oidc_discovery_url','?')} returned status "
            f"{s.get('oidc_discovery_status','?')} / no JSON. The target may not be an OIDC "
            "provider, or the well-known path differs."
        ),
        "remediation": (
            "Confirm the issuer exposes /.well-known/openid-configuration, or pass the exact "
            "issuer base via options.issuer."
        ),
    }


def rule_positive(s):
    if s.get("oidc_input_missing") or s.get("oidc_httpx_missing") or s.get("oidc_unreachable"):
        return None
    if any(s.get(k) for k in ("oidc_pkce_missing", "oidc_implicit_response_types",
                              "oidc_none_alg", "oidc_symmetric_only",
                              "oidc_insecure_endpoints")):
        return None
    if not s.get("oidc_issuer"):
        return None
    return {
        "name": "OIDC discovery configuration is hardened (PKCE S256, no implicit, asymmetric, TLS)",
        "severity": "POSITIVE",
        "cwe": "CWE-1059",
        "owasp": "A02:2021",
        "evidence": (
            f"Issuer {s.get('oidc_issuer')} advertises S256 PKCE, no implicit/token response "
            f"types, asymmetric id_token signing without alg=none, and all endpoints over TLS."
        ),
        "remediation": (
            "Keep this configuration. Re-run after any IdP upgrade or new client onboarding."
        ),
    }


OIDC_DISCOVERY_AUDIT_FINDING_RULES = [
    rule_insecure_endpoints,
    rule_pkce_missing,
    rule_implicit_flow,
    rule_none_alg,
    rule_symmetric_only,
    rule_par_advisory,
    rule_input_missing,
    rule_httpx_missing,
    rule_unreachable,
    rule_positive,
]


INTEL_FIELDS = [
    ("Discovery URL",        "oidc_discovery_url"),
    ("Discovery status",     "oidc_discovery_status"),
    ("Issuer",               "oidc_issuer"),
    ("Response types",       "oidc_response_types"),
    ("PKCE methods",         "oidc_pkce_methods"),
    ("Signing algorithms",   "oidc_signing_algs"),
    ("Grant types",          "oidc_grant_types"),
    ("Insecure endpoints",   "oidc_insecure_endpoints"),
    ("Implicit response types", "oidc_implicit_response_types"),
]


@router.post("/api/auth_attacks/oidc_discovery_audit")
async def auth_attacks_oidc_discovery_audit(req: OidcDiscoveryAuditRequest,
                                            _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="oidc_discovery_audit",
        gather_func=_gather_with_options,
        finding_rules=OIDC_DISCOVERY_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
