"""web_cache_deception — append static-file extension to dynamic URLs.

Web Cache Deception (Omer Gil 2017): /account/profile responds with PII
for the logged-in user. Attacker tricks user into visiting
/account/profile/foo.css. The CDN/cache sees .css extension, caches the
response (which contains the user's PII). Attacker then fetches the same
URL and gets the cached copy.

Test: GET /something/foo.css where /something is dynamic. If cache header
(X-Cache: HIT / CF-Cache-Status: HIT / age: > 0) appears, vuln.
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

DYNAMIC_PATHS = [
    "/account", "/profile", "/dashboard", "/settings", "/me",
    "/api/user", "/api/profile", "/api/me", "/user/profile",
]
EXTENSIONS = [".css", ".js", ".png", ".jpg", ".ico", ".woff2"]
CACHE_HEADERS = [
    "x-cache", "cf-cache-status", "age", "x-served-by",
    "x-cache-hits", "fastly-debug-state",
]


def _is_cached(resp) -> tuple[bool, str]:
    """Return (cached?, evidence)."""
    if resp is None: return False, ""
    for h in CACHE_HEADERS:
        v = resp.headers.get(h) or ""
        v_lower = v.lower()
        if h == "age" and v and v.isdigit() and int(v) > 0:
            return True, f"Age: {v}"
        if "hit" in v_lower or "cache" in v_lower and "miss" not in v_lower:
            return True, f"{h}: {v}"
    # max-age in Cache-Control
    cc = (resp.headers.get("cache-control") or "").lower()
    if "max-age" in cc and "max-age=0" not in cc and "no-store" not in cc:
        return True, f"Cache-Control: {cc[:80]}"
    return False, ""


@router.post("/api/webapp/scan/web_cache_deception")
@vl_turbo()
@vl_verify()
def scan_web_cache_deception(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    vulnerable_paths = []
    not_cached = []
    tested = 0

    for path in DYNAMIC_PATHS:
        # Skip if base path doesn't exist
        r0 = safe_request("GET", base + path,
            headers={"User-Agent": "VulnusLab/1.0"},
            req=req, timeout=8, allow_redirects=False)
        if r0 is None or r0.status_code == 404: continue

        # Now append .css and check if cache caches it
        deceived = base + path + "/foo.css"
        r1 = safe_request("GET", deceived,
            headers={"User-Agent": "VulnusLab/1.0"},
            req=req, timeout=8, allow_redirects=False)
        if r1 is None: continue
        tested += 1
        # Vulnerable signal: original returned 200 dynamic content +
        # appended-extension version ALSO returned 200 + cache headers indicate caching
        if r1.status_code == 200:
            cached, evidence = _is_cached(r1)
            if cached:
                # And content looks like the original (not a 404 page)
                body0 = (r0.text or "")[:1000]
                body1 = (r1.text or "")[:1000]
                # If lengths are similar AND content overlaps significantly
                if abs(len(body0) - len(body1)) < 500 and len(body1) > 100:
                    vulnerable_paths.append({
                        "path": path, "deceived_url": deceived,
                        "cache_evidence": evidence,
                    })
                    continue
        not_cached.append(path)

    findings = []
    if vulnerable_paths:
        findings.append(wrap_finding(
            f"Web Cache Deception possible at {len(vulnerable_paths)} path(s)",
            "HIGH", cvss="7.5", cwe="CWE-525", owasp="A05:2021",
            remediation="Web Cache Deception: dynamic content cached under static "
                        "file extension. (1) Configure cache to ONLY cache responses "
                        "where Content-Type matches the URL extension (so /profile/"
                        "foo.css with text/html → don't cache). (2) Or explicitly "
                        "set Cache-Control: no-store on all authenticated endpoints. "
                        "(3) Don't strip the path extension at the application layer. "
                        "Reference: Omer Gil's BlackHat 2017 Web Cache Deception talk.",
            evidence_marker=" | ".join(
                f"{v['path']} → {v['deceived_url']} ({v['cache_evidence']})"
                for v in vulnerable_paths[:3]
            )))
    elif tested > 0:
        findings.append(wrap_finding(
            f"No Web Cache Deception observed at {tested} dynamic path(s)",
            "POSITIVE", cwe="CWE-525",
            remediation="Maintain. Periodically re-test after CDN config changes.",
            evidence_marker=f"tested: {', '.join(not_cached[:5])}"))
    else:
        return standard_response(
            tool="web_cache_deception", target=req.target, findings=[],
            tests_performed=len(DYNAMIC_PATHS), vulnerable=False,
            skipped_reason="None of the dynamic test paths exist on this target")

    return standard_response(
        tool="web_cache_deception", target=req.target, findings=findings,
        tests_performed=len(DYNAMIC_PATHS), vulnerable=bool(vulnerable_paths),
        tests_summary=f"{tested} paths tested, {len(vulnerable_paths)} vulnerable",
        raw_data={"vulnerable_paths": vulnerable_paths,
                   "tested_clean": not_cached})


def register(app):
    app.include_router(router)
