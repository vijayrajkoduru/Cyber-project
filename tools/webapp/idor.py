"""IDOR — sequential-ID enumeration on /api/<resource>/<id> endpoints."""
import hashlib
import re
import time
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools._spa_state import load_spa_state
from tools._vl_core.turbo import vl_turbo

router = APIRouter()

_DEFAULT_PATTERNS = [
    "/api/Users/{id}", "/api/BasketItems/{id}", "/api/Feedbacks/{id}",
    "/api/Products/{id}", "/api/Recycles/{id}", "/api/SecurityQuestions/{id}",
    "/users/{id}", "/orders/{id}", "/invoices/{id}", "/messages/{id}",
]
_NUMERIC_ID_RE = re.compile(r"/(\d+)(/|$|\?)")


def _hash(text):
    return hashlib.md5((text or "")[:2000].encode("utf-8", errors="ignore")).hexdigest()


@router.post("/api/webapp/scan/idor")
@vl_turbo()
def scan_idor(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    has_auth = bool(getattr(req, "auth_cookie", None) or getattr(req, "auth_bearer", None))
    if not has_auth:
        return standard_response(tool="idor", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="IDOR test requires auth credentials — without a session, all unauthenticated paths return 401/403 by design.")

    spa = load_spa_state(req.target)
    patterns = list(_DEFAULT_PATTERNS)
    for url in list(spa.get("urls", [])) + list(spa.get("endpoints", {}).keys()):
        m = _NUMERIC_ID_RE.search(url)
        if m:
            templated = url[:m.start()+1] + "{id}" + url[m.end()-1:]
            if templated.count("{id}") == 1 and templated not in patterns:
                patterns.append(templated)

    findings, tests, confirmed, suppressed = [], 0, [], []

    # Strip auth from a copy of req for the unauth-probe sanity check.
    # We need to know: does this endpoint REQUIRE auth at all? If a /<id>
    # endpoint returns 200 to anyone, it is a public catalog by design
    # (e.g. /api/Products) and finding different responses for different
    # IDs is correct behaviour, NOT an IDOR.
    class _NoAuthReq:
        def __init__(self, real):
            self.target = real.target
            self.auth_cookie = None
            self.auth_bearer = None
    no_auth = _NoAuthReq(req)

    # VL-TURBO wall-clock cap: bail at 45s, report partial findings honestly.
    _wallclock_start = time.time()
    _WALLCLOCK_BUDGET = 45.0
    _bailed = False
    for pattern in patterns[:15]:
        if time.time() - _wallclock_start > _WALLCLOCK_BUDGET:
            _bailed = True; break
        # Step 1 — does unauth get 401/403 here? If not, it's a public endpoint.
        url1 = base + pattern.replace("{id}", "1")
        tests += 1
        unauth_r = safe_get(url1, req=no_auth, allow_redirects=False, timeout=10)
        if unauth_r is None:
            continue
        if unauth_r.status_code not in (401, 403):
            suppressed.append({"pattern": pattern,
                                "reason": "public_endpoint",
                                "unauth_status": unauth_r.status_code})
            continue

        # Step 2 — with auth, baseline ID=1 should return 200
        tests += 1
        r1 = safe_get(url1, req=req, allow_redirects=False, timeout=10)
        if r1 is None or r1.status_code not in (200, 304):
            continue
        hashes_seen = {1: _hash(r1.text or "")}

        # Step 3 — probe more IDs with auth
        for tid in (2, 3, 5, 10, 99):
            tests += 1
            ru = base + pattern.replace("{id}", str(tid))
            r = safe_get(ru, req=req, allow_redirects=False, timeout=10)
            if r is None or r.status_code != 200:
                continue
            hashes_seen[tid] = _hash(r.text or "")

        unique = set(hashes_seen.values())
        if len(unique) >= 3 and len(hashes_seen) >= 4:
            findings.append(wrap_finding(
                f"IDOR — {pattern} returns different records for different IDs (auth required, but no per-record authorization)",
                "HIGH", cvss="7.5", cwe="CWE-639", owasp="A01:2021",
                remediation=("Add server-side authorization on every record fetch: verify the "
                           "requesting user owns the record (or has been granted access) before returning data."),
                evidence_marker=f"{pattern}: unauth=HTTP{unauth_r.status_code} (gated), auth returned {len(unique)} distinct record hashes across IDs {sorted(hashes_seen.keys())}"))
            confirmed.append({"pattern": pattern,
                              "unauth_status": unauth_r.status_code,
                              "distinct_responses": len(unique),
                              "ids_tested": sorted(hashes_seen.keys())})

    summary = (f"IDOR: {tests} probes across {len(patterns[:15])} ID patterns "
               f"(auth=on) in {time.time() - _wallclock_start:.1f}s; "
               f"{len(suppressed)} public-endpoint FP(s) suppressed")
    if _bailed:
        summary += f" — VL-TURBO wall-clock bailed at {_WALLCLOCK_BUDGET}s"
    return standard_response(tool="idor", target=req.target, findings=findings,
        tests_performed=tests,
        tests_summary=summary,
        raw_data={"idor": {"confirmed": confirmed,
                            "suppressed_public_endpoints": suppressed,
                            "patterns_tested": patterns[:15],
                            "wallclock_bailed": _bailed}})


def register(app):
    app.include_router(router)
