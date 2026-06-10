"""Mass Assignment — POST forbidden fields to user/registration endpoints."""
import secrets, time
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_post, wrap_finding, standard_response)
from tools._spa_state import load_spa_state
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

_FORBIDDEN_FIELDS = {
    "role": "admin", "isAdmin": True, "is_admin": True,
    "verified": True, "emailVerified": True, "isVerified": True,
    "balance": 999999, "deluxeToken": "x",
}
_DEFAULT_PATHS = [
    "/api/Users", "/api/users", "/api/v1/users",
    "/api/register", "/api/auth/register", "/api/auth/signup",
    "/rest/user", "/register", "/signup",
]


def _contains(obj, val, key):
    if isinstance(obj, dict):
        if obj.get(key) == val:
            return True
        return any(_contains(c, val, key) for c in obj.values())
    if isinstance(obj, list):
        return any(_contains(c, val, key) for c in obj)
    return False


@router.post("/api/webapp/scan/mass_assignment")
@vl_turbo()
@vl_verify()
def scan_mass_assignment(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    spa = load_spa_state(req.target)
    candidates = list(_DEFAULT_PATHS)
    for url, info in (spa.get("endpoints") or {}).items():
        if isinstance(info, dict) and "POST" in (info.get("methods") or []):
            path = url.replace(base, "") or "/"
            if any(k in path.lower() for k in ("user", "register", "signup", "account")):
                if path not in candidates:
                    candidates.append(path)

    findings, tests, confirmed = [], 0, []
    canary_email = f"vlcanary-{secrets.token_hex(4)}@vulnuslab.example"
    # VL-TURBO wall-clock cap.
    _wallclock_start = time.time()
    _WALLCLOCK_BUDGET = 30.0
    _bailed = False
    for path in candidates[:8]:
        if time.time() - _wallclock_start > _WALLCLOCK_BUDGET:
            _bailed = True; break
        url = base + (path if path.startswith("/") else "/" + path)
        body = {"email": canary_email,
                "password": "VlLab-" + secrets.token_hex(6) + "!",
                **_FORBIDDEN_FIELDS}
        tests += 1
        r = safe_post(url, json=body, req=req,
                       headers={"Content-Type": "application/json"},
                       allow_redirects=False, timeout=10)
        if r is None or r.status_code not in (200, 201):
            continue
        try:
            data = r.json() if "json" in r.headers.get("Content-Type", "").lower() else None
        except Exception:
            data = None
        if not data:
            continue
        echoed = [k for k, v in _FORBIDDEN_FIELDS.items() if _contains(data, v, k)]
        if echoed:
            findings.append(wrap_finding(
                f"Mass Assignment — {path} accepted forbidden fields: {', '.join(echoed)}",
                "HIGH", cvss="8.1", cwe="CWE-915", owasp="A04:2021",
                remediation=("Use an explicit allow-list of fields the API will accept "
                           "from clients (whitelist). Strip everything else server-side "
                           "before persisting to the DB."),
                evidence_marker=f"POST {path} echoed forbidden field(s) {echoed} back in response"))
            confirmed.append({"path": path, "echoed_fields": echoed,
                              "status": r.status_code})

    summary = (f"Mass Assignment: {tests} probes with {len(_FORBIDDEN_FIELDS)} forbidden fields "
               f"in {time.time() - _wallclock_start:.1f}s")
    if _bailed:
        summary += f" — VL-TURBO wall-clock bailed at {_WALLCLOCK_BUDGET}s"
    return standard_response(tool="mass_assignment", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=summary,
        raw_data={"mass_assignment": {"confirmed": confirmed, "wallclock_bailed": _bailed}})


def register(app):
    app.include_router(router)
