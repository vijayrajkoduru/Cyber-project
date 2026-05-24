"""Webapp: Cache poisoning - unkeyed header injection (Param Miner-style)."""
import secrets
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, wrap_finding, standard_response

router = APIRouter()

# Headers that are typically NOT included in the cache key but may influence response
_FALLBACK_UNKEYED = ["X-Forwarded-Host","X-Forwarded-Server","X-Host","X-Original-URL","X-Rewrite-URL","X-Forwarded-For","X-Forwarded-Scheme","X-Forwarded-Proto","X-Original-Host","X-Custom-IP-Authorization"]

# AI-curated 62-entry list — extract unique header names from anywhere in
# the multiline HTTP-request payload (not just the request-line).
try:
    from tools._payloads.cache_poisoning_payloads import CACHE_POISONING_PAYLOADS as _AI_CP
    import re as _re
    _UNKEYED_HEADERS = list(_FALLBACK_UNKEYED)
    _seen = {h.lower() for h in _UNKEYED_HEADERS}
    # Find ALL header lines inside the payload (skip GET/POST/PUT request lines)
    for _p in _AI_CP:
        if not isinstance(_p, dict): continue
        for ln in _p.get("payload", "").splitlines():
            if ln.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "Host:")): continue
            m = _re.match(r"^([A-Z][A-Za-z0-9\-]{2,40})\s*:", ln)
            if m and m.group(1).lower() not in _seen:
                _UNKEYED_HEADERS.append(m.group(1))
                _seen.add(m.group(1).lower())
    _UNKEYED_HEADERS = _UNKEYED_HEADERS[:25]
except Exception:
    _UNKEYED_HEADERS = _FALLBACK_UNKEYED


@router.post("/api/webapp/cache_poisoning")
async def webapp_cache_poisoning(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    tests = 0
    canary = f"cachepoison-{secrets.token_hex(6)}.example"
    suspect = []
    
    # First verify caching is in play (look for X-Cache, CF-Cache-Status, age, etc.)
    try:
        r0 = requests.get(base + "/?cb=" + secrets.token_hex(4),
                          headers={"User-Agent":"VulnusLab/1.0"},
                          timeout=8, allow_redirects=False, verify=False)
        cache_headers = {k.lower(): v for k, v in r0.headers.items() if k.lower() in ("x-cache","cf-cache-status","age","x-served-by","x-cache-hits","via")}
        has_cache = bool(cache_headers)
    except Exception:
        cache_headers = {}
        has_cache = False
    
    if not has_cache:
        return standard_response(
            tool="cache_poisoning", target=req.target, findings=[],
            tests_performed=1,
            skipped_reason="No caching layer detected (X-Cache / CF-Cache-Status / Age headers absent)",
            raw_data={"cache_poisoning": {"cache_headers_found": []}},
        )
    
    for header in _UNKEYED_HEADERS:
        tests += 1
        cb = secrets.token_hex(6)
        url = f"{base}/?cb={cb}"
        try:
            r1 = requests.get(url, headers={header: canary, "User-Agent":"VulnusLab/1.0"},
                              timeout=8, allow_redirects=False, verify=False)
        except Exception:
            continue
        if canary not in (r1.text or "") and canary not in r1.headers.get("Location",""):
            continue
        # Header is reflected. Now check if it persists in a CLEAN follow-up (suggests cache poisoning)
        try:
            r2 = requests.get(url, headers={"User-Agent":"VulnusLab/1.0"},
                              timeout=8, allow_redirects=False, verify=False)
        except Exception:
            continue
        if canary in (r2.text or "") or canary in r2.headers.get("Location",""):
            suspect.append({"header": header, "url": url})
            findings.append(wrap_finding(
                f"Cache poisoning - '{header}: {canary}' persisted in a clean follow-up request (no header sent)",
                "HIGH",
                cvss="8.6", cwe="CWE-444",
                cwe_name="Inconsistent Interpretation of HTTP Requests (HTTP Request/Response Smuggling)",
                owasp="A05:2021",
                remediation=("Include all request-influencing headers in the cache key, OR strip "
                             f"untrusted headers (like {header}) at the edge before they reach the "
                             "origin. CDN/reverse proxy must not reflect attacker-controlled headers."),
                evidence_marker=f"GET {url} with {header}: {canary} -> canary cached; clean follow-up still serves it",
            ))

    return standard_response(
        tool="cache_poisoning", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Tested {tests} unkeyed-header inputs against detected cache layer ({list(cache_headers.keys())})",
        raw_data={"cache_poisoning": {"cache_headers": cache_headers, "suspect": suspect, "canary": canary}},
    )


def register(app):
    app.include_router(router)
