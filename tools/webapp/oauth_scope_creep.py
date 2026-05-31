"""oauth_scope_creep — flag OAuth auth-endpoint accepting over-broad scopes.

Probes the OAuth authorize endpoint with progressively broader scope
requests. A well-configured SP enforces scope allow-lists per client_id
— attacker shouldn't be able to request 'admin' or '*' scopes even
if their client_id only legitimately needs 'read'.

This is a passive probe: just send GET to authorize endpoint and look
at the rendered consent page / 400 error.
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)

router = APIRouter()

AUTH_PATHS = ["/oauth/authorize", "/oauth2/authorize", "/auth/authorize",
               "/connect/authorize", "/o/oauth2/v2/auth"]

# Successively-broader scope strings — well-configured server rejects these
TEST_SCOPES = [
    "openid",                       # OIDC baseline (should always work if SP supports OIDC)
    "openid profile email",
    "openid profile email admin",   # 'admin' should be rejected for non-admin clients
    "*",                            # wildcard scope
    "admin full_access *",
]


def _probe(url, params, req):
    return safe_request("GET", url, params=params,
        headers={"User-Agent": "VulnusLab/1.0"},
        req=req, timeout=8, allow_redirects=False)


@router.post("/api/webapp/scan/oauth_scope_creep")
def scan_oauth_scope_creep(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    endpoint = None

    for path in AUTH_PATHS:
        r = _probe(base + path, {}, req)
        if r is None: continue
        if r.status_code != 404:
            endpoint = base + path
            break

    if not endpoint:
        return standard_response(
            tool="oauth_scope_creep", target=req.target, findings=[],
            tests_performed=len(AUTH_PATHS), vulnerable=False,
            skipped_reason="No OAuth authorize endpoint at common paths")

    # Hit endpoint with various scopes — looking for consent page vs reject
    results = []
    for scope in TEST_SCOPES:
        r = _probe(endpoint, {
            "client_id": "test_client_vulnuslab",
            "response_type": "code",
            "redirect_uri": "https://localhost/cb",
            "scope": scope,
            "state": "xyz",
        }, req)
        if r is None: continue
        body = (r.text or "")[:5000].lower()
        # Reject-indicators (good)
        rejected = (r.status_code == 400 or
                    any(k in body for k in ("invalid_scope", "scope not allowed",
                                              "unknown scope", "client not allowed")))
        results.append({"scope": scope, "status": r.status_code,
                          "rejected": rejected,
                          "body_snippet": body[:200]})

    findings = []
    # Bug: wildcard scope ACCEPTED (no error)
    wildcard = next((r for r in results if r["scope"] == "*"), None)
    admin = next((r for r in results if "admin" in r["scope"]), None)

    if wildcard and not wildcard["rejected"]:
        findings.append(wrap_finding(
            "OAuth authorize accepts wildcard scope '*'",
            "MEDIUM", cvss="5.3", cwe="CWE-732", owasp="A01:2021",
            remediation="OAuth client_id should have explicit scope allow-list "
                        "enforced server-side. '*' wildcard should be rejected as "
                        "invalid_scope. Check OIDC config or auth-server config.",
            evidence_marker=f"GET {endpoint}?scope=* → HTTP {wildcard['status']} not rejected"))

    if admin and not admin["rejected"]:
        findings.append(wrap_finding(
            "OAuth authorize accepts arbitrary 'admin' scope",
            "MEDIUM", cvss="5.3", cwe="CWE-732", owasp="A01:2021",
            remediation="Test client requested 'admin' scope — server should "
                        "reject as invalid_scope (test client doesn't have admin "
                        "rights). If accepted, scope-creep attack possible: "
                        "attacker registers minimal client + requests admin scope + "
                        "user blindly approves = elevated tokens.",
            evidence_marker=f"GET {endpoint}?scope=...+admin → HTTP {admin['status']} not rejected"))

    if not findings:
        findings.append(wrap_finding(
            "OAuth scope validation looks proper",
            "POSITIVE", cwe="CWE-732",
            remediation="Maintain. Periodically audit per-client scope allow-lists.",
            evidence_marker=f"{len([r for r in results if r['rejected']])} of "
                              f"{len(results)} test scopes rejected"))

    return standard_response(
        tool="oauth_scope_creep", target=req.target, findings=findings,
        tests_performed=len(AUTH_PATHS) + len(TEST_SCOPES),
        vulnerable=any(f.get("severity") == "MEDIUM" for f in findings),
        tests_summary=f"endpoint: {endpoint}, "
                       f"{sum(1 for r in results if not r['rejected'])} of "
                       f"{len(results)} scopes accepted",
        raw_data={"endpoint": endpoint, "scope_test_results": results})


def register(app):
    app.include_router(router)
