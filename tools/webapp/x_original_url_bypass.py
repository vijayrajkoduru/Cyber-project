"""x_original_url_bypass — X-Original-URL / X-Rewrite-URL header auth bypass.

Some reverse proxies (IIS, certain nginx configs) honor X-Original-URL
or X-Rewrite-URL headers as the EFFECTIVE path — overriding the request
line. If the proxy applies its auth ruleset to the request-line URL but
then forwards X-Original-URL to the backend, attacker can bypass.

Test: GET / + X-Original-URL: /admin → if response looks like /admin
content rather than /, BUG.
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

HEADERS = ["X-Original-URL", "X-Rewrite-URL", "X-Override-URL",
            "X-HTTP-Method-Override", "X-Forwarded-Path"]
TARGETS = ["/admin", "/api/admin", "/.env", "/.git/config",
            "/api/internal", "/management"]


def _probe(url, headers, req):
    return safe_request("GET", url,
        headers={**headers, "User-Agent": "VulnusLab/1.0"},
        req=req, timeout=8, allow_redirects=False)


@router.post("/api/webapp/scan/x_original_url_bypass")
@vl_turbo()
@vl_verify()
def scan_x_original_url_bypass(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")

    bypasses = []

    for target in TARGETS:
        # Baseline: direct GET — get the status (expect 401/403)
        r_direct = _probe(base + target, {}, req)
        if r_direct is None: continue
        direct_status = r_direct.status_code
        direct_size = len(r_direct.content) if r_direct.content else 0

        # If target is publicly accessible already, test is moot
        if direct_status == 200: continue
        if direct_status == 404: continue

        # Try each rewrite header at /
        for hdr in HEADERS:
            r = _probe(base + "/", {hdr: target}, req)
            if r is None: continue
            # Bypass signal: GET / + X-Original-URL: /admin returns 200 with
            # different content vs baseline /
            if r.status_code == 200:
                # Compare body to "/" baseline (we don't have it, so just check
                # size differs significantly from a hello page)
                body = (r.text or "")[:1000].lower()
                # Heuristic: /admin response has admin-y text
                if any(t in body for t in ("admin", "internal", ".env", "config",
                                              "dashboard", "user list")):
                    bypasses.append({
                        "header": hdr, "target_path": target,
                        "direct_status": direct_status,
                        "bypass_status": r.status_code,
                    })
                    break  # one finding per target

    findings = []
    if bypasses:
        findings.append(wrap_finding(
            f"X-Original-URL / X-Rewrite-URL bypass at {len(bypasses)} path(s)",
            "CRITICAL", cvss="9.0", cwe="CWE-444", owasp="A01:2021",
            remediation="Reverse proxy applies auth rules to request-line but "
                        "forwards rewrite header to backend, which uses header "
                        "value as effective path. Fix: strip X-Original-URL, "
                        "X-Rewrite-URL, X-Override-URL, X-Forwarded-Path at the "
                        "edge BEFORE forwarding (nginx: 'proxy_set_header "
                        "X-Original-URL \"\";'). Or disable header-based URL "
                        "rewriting at the backend.",
            evidence_marker=" | ".join(
                f"{b['header']}: {b['target_path']} (direct: HTTP {b['direct_status']}, "
                f"bypass: HTTP {b['bypass_status']})"
                for b in bypasses[:3]
            )))
    else:
        findings.append(wrap_finding(
            "No X-Original-URL / X-Rewrite-URL bypasses detected",
            "POSITIVE", cwe="CWE-444",
            remediation="Maintain. Continue stripping override headers at edge.",
            evidence_marker=f"tested {len(TARGETS)} sensitive paths × {len(HEADERS)} headers"))

    return standard_response(
        tool="x_original_url_bypass", target=req.target, findings=findings,
        tests_performed=len(TARGETS) * (1 + len(HEADERS)),
        vulnerable=bool(bypasses),
        tests_summary=f"{len(bypasses)} bypass(es) found",
        raw_data={"bypasses": bypasses})


def register(app):
    app.include_router(router)
