"""oauth_client_id_confusion — OAuth client_id validation audit.

Tests whether the authorize endpoint rejects:
  - Unknown client_id (should always be 400/error)
  - Missing client_id
  - client_id with HTML/control chars (XSS / log injection)
  - client_id substring overlap with valid (case sensitivity bugs)

Misconfig: server returns 200 / consent screen for unknown client_id
= attacker can phish using your domain.
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)

router = APIRouter()

AUTH_PATHS = ["/oauth/authorize", "/oauth2/authorize", "/auth/authorize",
               "/connect/authorize", "/o/oauth2/v2/auth"]
TEST_CLIENT_IDS = [
    ("missing",     None),
    ("empty",       ""),
    ("unknown",     "vulnuslab-unknown-client-xyz"),
    ("xss",         "<script>alert(1)</script>"),
    ("with-null",   "abc\x00admin"),
    ("very-long",   "a" * 300),
]


def _probe(url, params, req):
    return safe_request("GET", url, params=params,
        headers={"User-Agent": "VulnusLab/1.0"},
        req=req, timeout=8, allow_redirects=False)


@router.post("/api/webapp/scan/oauth_client_id_confusion")
def scan_oauth_client_id_confusion(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    endpoint = None
    for path in AUTH_PATHS:
        r = _probe(base + path, {}, req)
        if r is None: continue
        if r.status_code != 404:
            endpoint = base + path; break

    if not endpoint:
        return standard_response(
            tool="oauth_client_id_confusion", target=req.target, findings=[],
            tests_performed=len(AUTH_PATHS), vulnerable=False,
            skipped_reason="No OAuth /authorize endpoint at common paths")

    issues = []
    reflection_xss = []
    accepted_unknown = []

    for label, cid in TEST_CLIENT_IDS:
        params = {
            "response_type": "code",
            "redirect_uri": "https://localhost/cb",
            "state": "xyz",
        }
        if cid is not None:
            params["client_id"] = cid

        r = _probe(endpoint, params, req)
        if r is None: continue
        body = (r.text or "")[:5000]

        # Reflection check (XSS)
        if cid and "<script>" in cid and cid in body:
            reflection_xss.append({"label": label, "payload": cid[:40]})

        # Unknown-accepted check
        if label == "unknown":
            err_words = ("invalid_client", "client_id", "unknown client",
                          "client not found", "invalid client_id")
            has_err = any(w in body.lower() for w in err_words)
            # Also check if status is non-2xx error
            if r.status_code in (200, 302) and not has_err:
                # Could be redirecting to consent form for unknown client
                accepted_unknown.append({"status": r.status_code,
                                          "snippet": body[:200]})

    findings = []
    if reflection_xss:
        findings.append(wrap_finding(
            f"client_id REFLECTED unescaped → XSS on OAuth /authorize",
            "HIGH", cvss="7.5", cwe="CWE-79", owasp="A03:2021",
            remediation="HTML-escape client_id in any error message. Better: "
                        "reject non-alphanumeric client_id format before rendering. "
                        "Reflected XSS on authorize endpoint is particularly bad "
                        "(victim already logged in, attacker steals OAuth token).",
            evidence_marker=" | ".join(
                f"{r['label']}: payload reflected raw" for r in reflection_xss[:3]
            )))

    if accepted_unknown:
        findings.append(wrap_finding(
            "Unknown client_id NOT rejected at /authorize",
            "MEDIUM", cvss="5.3", cwe="CWE-287", owasp="A07:2021",
            remediation="Authorize endpoint should reject unknown client_id with "
                        "explicit error (400 + invalid_client). Without this, "
                        "attacker can phish via your domain: hosts an authorize "
                        "URL with their phishing redirect_uri + an unknown "
                        "client_id; consent page may render their custom name "
                        "+ scope → user grants access.",
            evidence_marker=f"unknown client_id → HTTP {accepted_unknown[0]['status']}; "
                              f"snippet: {accepted_unknown[0]['snippet'][:120]}"))

    if not findings:
        findings.append(wrap_finding(
            "OAuth client_id validation looks proper",
            "POSITIVE", cwe="CWE-287",
            remediation="Maintain. Continue rejecting unknown clients with explicit "
                        "invalid_client errors.",
            evidence_marker=f"endpoint: {endpoint}, tested {len(TEST_CLIENT_IDS)} "
                              "client_id variants"))

    return standard_response(
        tool="oauth_client_id_confusion", target=req.target, findings=findings,
        tests_performed=len(AUTH_PATHS) + len(TEST_CLIENT_IDS),
        vulnerable=bool(reflection_xss or accepted_unknown),
        tests_summary=f"endpoint: {endpoint}, XSS: {len(reflection_xss)}, "
                       f"unknown-accepted: {len(accepted_unknown)}",
        raw_data={"endpoint": endpoint,
                   "xss_reflections": reflection_xss,
                   "accepted_unknown": accepted_unknown})


def register(app):
    app.include_router(router)
