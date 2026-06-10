"""Force-browse scanner — uses tools/_payloads/force_browse.py (595 paths)."""
import hashlib, secrets, time
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools._payloads.force_browse import FORCE_BROWSE_PATHS
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()
_MAX_PATHS = 200  # top-severity slice — politeness + speed


def _fp(r):
    body = (r.text or "")[:2000]
    return f"{r.status_code}:{hashlib.md5(body.encode('utf-8', errors='ignore')).hexdigest()}"


def _cvss(sev):
    return {"HIGH": "7.5", "MEDIUM": "5.3", "LOW": "3.1"}.get(sev, "3.1")


@router.post("/api/webapp/scan/force_browse")
@vl_turbo()
@vl_verify(check_spa=True)
def scan_force_browse(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")

    # SPA-shell baseline — kills FPs on Angular/React/Vue apps
    canary = "/_vl_canary_" + secrets.token_hex(6) + ".bogus"
    cr = safe_get(base + canary, req=req, allow_redirects=False, timeout=8)
    canary_fp = _fp(cr) if cr is not None else None
    spa_shell = cr is not None and cr.status_code == 200

    paths_sorted = sorted(FORCE_BROWSE_PATHS,
                          key=lambda p: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(p.get("severity", "LOW"), 3))
    paths_to_test = paths_sorted[:_MAX_PATHS]

    findings, tests, confirmed, suppressed = [], 0, [], 0
    by_cat = {}
    # VL-TURBO wall-clock cap: 200 paths × 8s = up to 27 min without cap.
    _wallclock_start = time.time()
    _WALLCLOCK_BUDGET = 60.0
    _bailed = False
    for entry in paths_to_test:
        if time.time() - _wallclock_start > _WALLCLOCK_BUDGET:
            _bailed = True; break
        path = entry.get("path", "")
        if not path.startswith("/"):
            path = "/" + path
        category = entry.get("category", "unknown")
        severity = entry.get("severity", "LOW")
        tests += 1
        r = safe_get(base + path, req=req, allow_redirects=False, timeout=8)
        if r is None or r.status_code != 200:
            continue
        if spa_shell and _fp(r) == canary_fp:
            suppressed += 1
            continue
        # Skip empty/tiny generic 200s (defensive)
        if len(r.content) < 50:
            continue
        findings.append(wrap_finding(
            f"Sensitive path exposed: {path}",
            severity, cvss=_cvss(severity),
            cwe="CWE-538", owasp="A05:2021",
            remediation=f"Block public access to {path} at the web server / WAF level.",
            evidence_marker=f"GET {path} → HTTP 200, {len(r.content)} bytes (category={category})"))
        confirmed.append({"path": path, "category": category, "severity": severity,
                          "status": r.status_code, "bytes": len(r.content)})
        by_cat[category] = by_cat.get(category, 0) + 1

    summary = (f"Force-browse: {tests} paths probed (top-{_MAX_PATHS} by severity) in "
               f"{time.time() - _wallclock_start:.1f}s; "
               f"{len(findings)} sensitive paths found; "
               f"{suppressed} SPA-shell FP(s) suppressed")
    if _bailed:
        summary += f" — VL-TURBO wall-clock bailed at {_WALLCLOCK_BUDGET}s"
    return standard_response(tool="force_browse", target=req.target,
        findings=findings, tests_performed=tests, tests_summary=summary,
        raw_data={"force_browse": {"confirmed": confirmed, "by_category": by_cat,
                                    "spa_shell_mode": spa_shell,
                                    "library_size": len(FORCE_BROWSE_PATHS)}})


def register(app):
    app.include_router(router)
