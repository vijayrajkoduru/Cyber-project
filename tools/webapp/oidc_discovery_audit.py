"""oidc_discovery_audit — fetch + audit /.well-known/openid-configuration.

OIDC providers MUST expose discovery at well-known endpoint per OIDC spec.
This scanner fetches the doc and flags risky configs:
  - id_token_signing_alg_values supports 'none' or HS256
  - token_endpoint accepts client_secret_post (less secure than _jwt)
  - response_types_supported includes 'id_token token' (implicit flow — bad)
  - jwks_uri loadable + has reasonable keys
  - revocation_endpoint missing
"""
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

WELL_KNOWN_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/openid_configuration",
    "/oauth/.well-known/openid-configuration",
    "/auth/.well-known/openid-configuration",
    "/oidc/.well-known/openid-configuration",
]


@router.post("/api/webapp/scan/oidc_discovery_audit")
@vl_turbo()
@vl_verify()
def scan_oidc_discovery_audit(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")

    discovery = None
    discovery_url = None

    def _probe(path):
        r = safe_request("GET", base + path,
            headers={"User-Agent": "VulnusLab/1.0", "Accept": "application/json"},
            req=req, timeout=8, allow_redirects=True)
        if r is None or r.status_code != 200: return None
        try:
            data = r.json()
        except Exception:
            return None
        if "issuer" in data and "authorization_endpoint" in data:
            return (base + path, data)
        return None

    # VL-TURBO deep: parallelize 5 discovery probes via pool(5).
    # Was ~40s sequential, now ~8s parallel. First-match priority preserved.
    disc_results = []
    with ThreadPoolExecutor(max_workers=min(5, len(WELL_KNOWN_PATHS))) as pool:
        for result in pool.map(_probe, WELL_KNOWN_PATHS, timeout=21):
            disc_results.append(result)
    for r in disc_results:
        if r is not None:
            discovery_url, discovery = r
            break

    if not discovery:
        return standard_response(
            tool="oidc_discovery_audit", target=req.target,
            findings=[wrap_finding(
                "No OIDC discovery endpoint found",
                "POSITIVE", cwe="CWE-200",
                remediation="App doesn't act as OIDC provider — no OIDC-specific "
                            "config to audit. If you DO have an OIDC IdP, expose the "
                            "well-known endpoint for client interop.",
                evidence_marker=f"checked {WELL_KNOWN_PATHS}")],
            tests_performed=len(WELL_KNOWN_PATHS), vulnerable=False,
            tests_summary="No OIDC")

    findings = []
    issues = []

    # Signing algorithm audit
    algs = discovery.get("id_token_signing_alg_values_supported") or []
    if "none" in algs:
        issues.append(("id_token_signing_alg 'none' supported — accepts unsigned tokens",
                        "CRITICAL"))
    elif any(a.startswith("HS") for a in algs) and not any(a.startswith("RS") or a.startswith("ES") for a in algs):
        issues.append(("Only HMAC (HS*) algorithms — client-secret known to BOTH "
                        "client + server (vs. RS/ES which use asymmetric keys)",
                        "MEDIUM"))

    # Implicit flow detection
    rt = discovery.get("response_types_supported") or []
    implicit = [r for r in rt if "token" in r and "code" not in r]
    if implicit:
        issues.append((f"Implicit flow supported ({', '.join(implicit[:2])}) — "
                        "token returned in URL fragment, leaks via Referer/history",
                        "MEDIUM"))

    # Token endpoint auth method
    auth_methods = discovery.get("token_endpoint_auth_methods_supported") or []
    if "client_secret_post" in auth_methods and "client_secret_jwt" not in auth_methods \
            and "private_key_jwt" not in auth_methods:
        issues.append(("Token endpoint only supports client_secret_post — credentials "
                        "in POST body (loggable). Add client_secret_jwt or "
                        "private_key_jwt for better security",
                        "LOW"))

    # PKCE support audit
    pkce = discovery.get("code_challenge_methods_supported") or []
    if not pkce or "S256" not in pkce:
        issues.append(("PKCE (code_challenge_methods_supported) missing S256 — "
                        "public clients vulnerable to auth-code interception",
                        "MEDIUM"))

    # Revocation + introspection
    if not discovery.get("revocation_endpoint"):
        issues.append(("No revocation_endpoint declared — tokens can't be "
                        "explicitly revoked on logout",
                        "LOW"))

    # JWKS reachability
    jwks_uri = discovery.get("jwks_uri")
    if jwks_uri:
        r_jwks = safe_request("GET", jwks_uri,
            headers={"User-Agent": "VulnusLab/1.0"},
            req=req, timeout=8, allow_redirects=True)
        if r_jwks is None or r_jwks.status_code != 200:
            issues.append((f"jwks_uri {jwks_uri} unreachable (HTTP "
                            f"{r_jwks.status_code if r_jwks else 'no-resp'}) — "
                            "RP can't verify tokens",
                            "HIGH"))

    if issues:
        sev = "CRITICAL" if any(s == "CRITICAL" for _, s in issues) else \
              "HIGH" if any(s == "HIGH" for _, s in issues) else \
              "MEDIUM" if any(s == "MEDIUM" for _, s in issues) else "LOW"
        cvss = {"CRITICAL": "9.8", "HIGH": "7.5", "MEDIUM": "5.3", "LOW": "3.5"}[sev]
        findings.append(wrap_finding(
            f"OIDC config issues ({len(issues)})",
            sev, cvss=cvss, cwe="CWE-287", owasp="A07:2021",
            remediation="Tune OIDC discovery to current best practices: "
                        "remove alg=none, prefer RS256/ES256 over HS256, "
                        "disable implicit flow, require PKCE S256, expose "
                        "revocation endpoint. Follow RFC 9700 OAuth 2.0 Security "
                        "BCP.",
            evidence_marker=" | ".join(f"{m} [{s}]" for m, s in issues[:5])))
    else:
        findings.append(wrap_finding(
            "OIDC config looks well-configured",
            "POSITIVE", cwe="CWE-287",
            remediation="Maintain. Periodically re-audit against RFC 9700.",
            evidence_marker=f"issuer: {discovery.get('issuer','?')[:60]} | "
                              f"algs: {algs} | rt: {rt}"))

    return standard_response(
        tool="oidc_discovery_audit", target=req.target, findings=findings,
        tests_performed=len(WELL_KNOWN_PATHS) + (1 if jwks_uri else 0),
        vulnerable=bool(issues),
        tests_summary=f"OIDC at {discovery_url}, {len(issues)} issues",
        raw_data={"discovery_url": discovery_url, "issuer": discovery.get("issuer"),
                   "algs": algs, "response_types": rt,
                   "issues": [{"desc": m, "severity": s} for m, s in issues]})


def register(app):
    app.include_router(router)
