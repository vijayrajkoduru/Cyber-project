"""Webapp: Cache poisoning - unkeyed header injection (Param Miner-style) — VL-TURBO."""
import asyncio
import secrets
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, wrap_finding, standard_response
from tools._vl_core.verify import vl_verify

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
@vl_verify()
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
    
    # VL-TURBO: phase 1 — parallel injection probes; phase 2 — parallel persistence checks
    sem = asyncio.Semaphore(15)

    def _sync_get(url, extra_headers=None):
        h = {"User-Agent": "VulnusLab/1.0"}
        if extra_headers:
            h.update(extra_headers)
        try:
            return requests.get(url, headers=h, timeout=4, allow_redirects=False, verify=False)
        except Exception:
            return None

    async def _probe(url, extra=None):
        async with sem:
            return await asyncio.to_thread(_sync_get, url, extra)

    # Phase 1: send each header with the canary
    probes = []  # (header, url)
    for header in _UNKEYED_HEADERS:
        cb = secrets.token_hex(6)
        probes.append((header, f"{base}/?cb={cb}"))
    try:
        injection_results = await asyncio.wait_for(
            asyncio.gather(*(_probe(u, {h: canary}) for h, u in probes)), timeout=45
        )
    except asyncio.TimeoutError:
        injection_results = [None] * len(probes)

    tests = len(probes)
    # Phase 2: for each "reflected" hit, send a clean follow-up to test cache persistence
    reflected = []
    for (header, url), r1 in zip(probes, injection_results):
        if r1 is None: continue
        if canary not in (r1.text or "") and canary not in r1.headers.get("Location", ""):
            continue
        reflected.append((header, url))

    try:
        persist_results = await asyncio.wait_for(
            asyncio.gather(*(_probe(u) for _, u in reflected)), timeout=30
        ) if reflected else []
    except asyncio.TimeoutError:
        persist_results = [None] * len(reflected)

    # Phase 3: evaluate
    for (header, url), r2 in zip(reflected, persist_results):
        if r2 is None:
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
