"""path_normalization_bypass — URL-encoding tricks for auth bypass.

Reverse proxies (nginx/Apache/CloudFront/CloudFlare) and back-ends parse
paths slightly differently. Attacker abuses this by submitting:
  - %2e%2e (encoded ..)
  - %2f%2e%2e%2f (encoded /../)
  - /admin%23 (URL-encoded fragment)
  - /admin;foo=bar (path parameters)
  - //admin (double-slash)

Goal: reach a protected endpoint that the proxy thinks is non-protected.
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

# (protected_path, normalized_form, attack_form)
# Baseline: GET /admin → expect 401/403/404. If any encoding returns 200, BUG.
PROBES = [
    ("/admin", "/admin",
     ["/admin/", "//admin", "/./admin", "/%61dmin",
      "/admin%23", "/admin;jsessionid=x", "/admin%2f..%2f"]),
    ("/admin/users", "/admin/users",
     ["/admin%2fusers", "/%2e/admin/users", "/admin/%2e%2eusers"]),
    ("/api/admin", "/api/admin",
     ["/api/admin/", "/api/./admin", "/api/admin%23"]),
    ("/.git/config", "/.git/config",
     ["/.git%2fconfig", "/%2e.git/config", "/x/../.git/config"]),
    ("/.env", "/.env",
     ["/.env%00.html", "/x/../.env", "/x/.env"]),
]


def _get(url, req):
    return safe_request("GET", url,
        headers={"User-Agent": "VulnusLab/1.0"},
        req=req, timeout=8, allow_redirects=False)


@router.post("/api/webapp/scan/path_normalization_bypass")
@vl_turbo()
@vl_verify()
def scan_path_normalization_bypass(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")

    bypasses = []
    not_present = []

    for original, normal, encodings in PROBES:
        # Baseline: GET original
        r_orig = _get(base + original, req)
        if r_orig is None:
            continue
        orig_status = r_orig.status_code

        # If original returns 200 (publicly accessible), the test is meaningless
        if orig_status == 200:
            continue
        # If original returns 404, the endpoint doesn't exist
        if orig_status == 404:
            not_present.append(original)
            continue

        # Original is protected (401/403). Now try encodings.
        bypass_paths = []
        for enc in encodings:
            r = _get(base + enc, req)
            if r is None: continue
            # Bypass if status flipped to 200 (or 30x to a content page, not error)
            if r.status_code == 200:
                bypass_paths.append({"encoding": enc, "status": 200,
                                      "size": len(r.content) if r.content else 0})
            elif r.status_code in (301, 302):
                loc = r.headers.get("location", "")
                if "error" not in loc.lower() and "login" not in loc.lower():
                    bypass_paths.append({"encoding": enc, "status": r.status_code,
                                          "redirect": loc[:80]})

        if bypass_paths:
            bypasses.append({"original": original, "baseline_status": orig_status,
                              "bypass_paths": bypass_paths})

    findings = []
    if bypasses:
        findings.append(wrap_finding(
            f"PATH-NORMALIZATION BYPASS at {len(bypasses)} endpoint(s) — auth bypass",
            "CRITICAL", cvss="9.0", cwe="CWE-22", owasp="A01:2021",
            remediation="The reverse proxy + back-end parse paths differently — "
                        "attacker reaches protected resource via encoded variant. "
                        "Fixes: (1) configure proxy to normalize paths BEFORE auth "
                        "check (nginx 1.21+ `path_compress on`); (2) reject "
                        "requests with %2e, %2f, %5c at proxy layer; (3) at "
                        "application layer, normalize path THEN apply auth in "
                        "same step. Test orientations from PortSwigger's "
                        "'URL normalization bypass' research.",
            evidence_marker=" | ".join(
                f"{b['original']} ({b['baseline_status']}) bypassed via: "
                + ", ".join(p['encoding'] for p in b['bypass_paths'][:3])
                for b in bypasses[:3]
            )))
    elif not_present and not bypasses:
        return standard_response(
            tool="path_normalization_bypass", target=req.target,
            findings=[wrap_finding(
                f"Tested {len(PROBES)} paths — {len(not_present)} return 404 (don't exist), "
                f"none of the existing ones were bypassed",
                "POSITIVE", cwe="CWE-22",
                remediation="Maintain proxy-level path normalization. Test deeper "
                            "with PortSwigger Burp + path-conversion lab.",
                evidence_marker=f"missing: {not_present[:3]}; no bypasses found")],
            tests_performed=len(PROBES), vulnerable=False,
            tests_summary="No bypass found")
    else:
        findings.append(wrap_finding(
            f"No path-normalization bypasses across {len(PROBES) - len(not_present)} reachable paths",
            "POSITIVE", cwe="CWE-22",
            remediation="Maintain. Test new admin paths with same patterns.",
            evidence_marker=f"tested {sum(len(p[2]) for p in PROBES)} encoded variants"))

    return standard_response(
        tool="path_normalization_bypass", target=req.target, findings=findings,
        tests_performed=sum(1 + len(p[2]) for p in PROBES),
        vulnerable=bool(bypasses),
        tests_summary=f"{len(bypasses)} bypass(es) found",
        raw_data={"bypasses": bypasses, "paths_not_present": not_present})


def register(app):
    app.include_router(router)
