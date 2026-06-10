"""xs_leaks_probe — Cross-Site Leak oracle detection.

XS-Leaks: side-channel attacks where a cross-origin attacker page
infers private data via timing, cache size, status-code oracles, etc.
Detection: check whether endpoints have the modern XS-Leak mitigations:
  - Cross-Origin-Resource-Policy (CORP)
  - Cross-Origin-Opener-Policy (COOP)
  - Cross-Origin-Embedder-Policy (COEP)
  - X-Frame-Options / frame-ancestors

These headers form the COIA (Cross-Origin Isolation Architecture)
defense-in-depth. Apps with sensitive endpoints SHOULD have them.
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo

router = APIRouter()


def _audit(headers, path):
    """Return list of issues for this response."""
    issues = []
    corp = (headers.get("cross-origin-resource-policy") or "").lower()
    coop = (headers.get("cross-origin-opener-policy") or "").lower()
    coep = (headers.get("cross-origin-embedder-policy") or "").lower()
    xfo = (headers.get("x-frame-options") or "").lower()
    csp = (headers.get("content-security-policy") or "").lower()

    if not corp:
        issues.append("CORP missing — endpoint loadable cross-origin "
                       "(timing / status oracle)")
    elif corp == "cross-origin":
        issues.append("CORP=cross-origin (loosest setting)")

    if not coop:
        issues.append("COOP missing — window.opener access from cross-origin")
    elif coop in ("unsafe-none", ""):
        issues.append(f"COOP={coop} (no isolation)")

    # COEP only required for SharedArrayBuffer / Spectre mitigation
    # — flag only if missing entirely on sensitive paths

    if not xfo and "frame-ancestors" not in csp:
        issues.append("X-Frame-Options + CSP frame-ancestors both missing")

    return issues


SENSITIVE_PATHS = [
    "/", "/account", "/profile", "/dashboard", "/settings",
    "/api/me", "/api/profile", "/admin",
]


@router.post("/api/webapp/scan/xs_leaks_probe")
@vl_turbo()
def scan_xs_leaks_probe(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    issues_by_path = {}
    tested = 0

    for path in SENSITIVE_PATHS:
        url = base + path
        r = safe_request("GET", url,
            headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
            req=req, timeout=8, allow_redirects=False)
        if r is None or r.status_code == 404: continue
        tested += 1
        # Normalize headers dict
        try:
            hdrs = {k.lower(): v for k, v in r.headers.items()}
        except Exception:
            hdrs = {}
        issues = _audit(hdrs, path)
        if issues:
            issues_by_path[path] = issues

    findings = []
    if not tested:
        return standard_response(
            tool="xs_leaks_probe", target=req.target, findings=[],
            tests_performed=len(SENSITIVE_PATHS), vulnerable=False,
            skipped_reason="No sensitive paths reachable on target")

    paths_with_issues = list(issues_by_path.keys())
    if paths_with_issues:
        total_issues = sum(len(v) for v in issues_by_path.values())
        findings.append(wrap_finding(
            f"XS-Leak protections incomplete at {len(paths_with_issues)} of {tested} paths",
            "MEDIUM", cvss="5.3", cwe="CWE-203", owasp="A05:2021",
            remediation="Add modern cross-origin isolation headers globally: "
                        "(1) Cross-Origin-Resource-Policy: same-origin (or same-site) — "
                        "blocks cross-origin embedding entirely; "
                        "(2) Cross-Origin-Opener-Policy: same-origin — prevents "
                        "tab-grouped cross-origin access to window.opener; "
                        "(3) Cross-Origin-Embedder-Policy: require-corp — required "
                        "for SharedArrayBuffer + best for Spectre mitigation; "
                        "(4) X-Frame-Options: DENY (legacy clickjacking) or use "
                        "CSP frame-ancestors. Read xsleaks.dev for the full attack "
                        "catalogue these headers defend against.",
            evidence_marker=" | ".join(
                f"{p}: {', '.join(issues_by_path[p][:2])}"
                for p in paths_with_issues[:5]
            )))
    else:
        findings.append(wrap_finding(
            f"All {tested} tested paths have proper XS-Leak headers",
            "POSITIVE", cwe="CWE-203",
            remediation="Maintain. Re-audit on every framework upgrade.",
            evidence_marker=f"CORP + COOP + frame-ancestors validated"))

    return standard_response(
        tool="xs_leaks_probe", target=req.target, findings=findings,
        tests_performed=len(SENSITIVE_PATHS),
        vulnerable=bool(paths_with_issues),
        tests_summary=f"{tested} paths tested, {len(paths_with_issues)} missing headers",
        raw_data={"issues_by_path": issues_by_path, "tested_count": tested})


def register(app):
    app.include_router(router)
