"""Exposed Sensitive Files — 232-path AI-curated dictionary with SPA-baseline FP suppression.

Path dictionary: tools/_payloads/vuln/exposed_files_paths.json (loaded
once at import). Falls back to a 31-entry hardcoded baseline if missing.

A SPA (React/Angular/Vue/Next) returns 200 OK + the SPA shell HTML for
ANY path, including /.env, /.git/config, etc. Without a baseline check
these all match generic markers and produce false-positive CRITICALs.
"""
import hashlib
import re
import secrets
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
from tools.webapp._webapp_common import vuln_response, precheck_target
from tools._payloads.webapp._loader import load_json
from tools._vl_core.turbo import vl_turbo
router = APIRouter()

_FALLBACK_PATHS = [
    (".env",                r"[A-Z_]+\s*=\s*\S",            "CRITICAL","9.1",".env exposes environment variables"),
    (".env.production",     r"[A-Z_]+\s*=\s*\S",            "CRITICAL","9.8",".env.production exposed — prod credentials leaked"),
    (".git/config",         r"\[core\]|\[remote",           "HIGH",    "7.5",".git/config exposed — repo can be reconstructed"),
    ("wp-config.php.bak",   r"DB_PASSWORD|DB_USER",         "CRITICAL","9.8","wp-config.php.bak — WordPress DB credentials leaked"),
    ("backup.sql",          r"CREATE TABLE|INSERT INTO",    "CRITICAL","9.1","Database backup (.sql) exposed publicly"),
    (".aws/credentials",    r"aws_access_key_id|\[default\]","CRITICAL","9.8","AWS credentials exposed"),
    (".ssh/id_rsa",         r"-----BEGIN .*PRIVATE KEY-----","CRITICAL","9.8","SSH private key exposed"),
    (".htpasswd",           r":\$\w+\$",                    "CRITICAL","9.1",".htpasswd exposed — password hashes leaked"),
]
_loaded = load_json("exposed_files_paths")
if isinstance(_loaded, list) and _loaded:
    _PATHS = [(e["path"], e["marker"], e["severity"], e["cvss"], e["text"]) for e in _loaded
              if all(k in e for k in ("path","marker","severity","cvss","text"))]
else:
    _PATHS = _FALLBACK_PATHS


def _match(body, pat):
    if pat is None:
        return len(body or "") > 50
    try:
        return re.search(pat, body or "", re.IGNORECASE) is not None
    except Exception:
        return False


def _fingerprint(r):
    if r is None:
        return None
    body = (r.text or "")[:2000]
    h = hashlib.md5(body.encode("utf-8", errors="ignore")).hexdigest()
    return f"{r.status_code}:{len(r.content)}:{h}"


@router.post("/api/webapp/scan/exposed_files")
@vl_turbo()
def scan_exposed_files(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    unreachable = precheck_target(base, req, active_probes=False)  # file-existence GETs — WAF passes through
    if unreachable:
        return vuln_response(tool="exposed_files", target=req.target, findings=[],
            tested=1, skipped_reason=unreachable)

    # SPA-shell baseline: a guaranteed-nonexistent path tells us what the
    # site returns for "404-equivalent". On a static / non-SPA site this
    # comes back as a real 404 (different fingerprint). On a SPA it returns
    # the same 200 shell as any other unknown path — any match below that
    # equals the baseline is the SPA shell, not a real file.
    canary_path = "/_vl_canary_" + secrets.token_hex(8) + ".bogus"
    canary = safe_get(f"{base}{canary_path}", req=req, allow_redirects=False, timeout=8)
    baseline_fp = _fingerprint(canary)
    spa_mode = canary is not None and canary.status_code == 200

    # SPEED-V2 — parallelise the 232-path probe with a thread pool (16 workers).
    # Sequential was ~30 min on slow targets; parallel is ~30-60s. Workers
    # each call safe_get which uses the `requests` library (thread-safe).
    # Wall-clock cap stops the whole pool at 60s regardless of pending paths.
    _wallclock_start = time.time()
    _WALLCLOCK_BUDGET = 60.0
    _bailed = False

    def _probe_one(entry):
        path, marker, sev, cvss, text = entry
        r = safe_get(f"{base}/{path}", req=req, allow_redirects=False, timeout=8)
        if r is None or r.status_code != 200:
            return None
        probe_fp = _fingerprint(r)
        if spa_mode and probe_fp == baseline_fp:
            return ("suppressed", path)
        if not _match((r.text or "")[:4000], marker):
            return None
        return ("hit", path, marker, sev, cvss, text)

    findings, matches, suppressed = [], [], []
    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = {pool.submit(_probe_one, entry): entry for entry in _PATHS}
        for fut in as_completed(futures):
            if time.time() - _wallclock_start > _WALLCLOCK_BUDGET:
                _bailed = True
                # cancel still-pending futures; running ones finish on their own
                for pending in futures:
                    if not pending.done():
                        pending.cancel()
                break
            try:
                result = fut.result()
            except Exception:
                continue
            if result is None:
                continue
            if result[0] == "suppressed":
                suppressed.append({"path": result[1], "reason": "matches_spa_shell"})
                continue
            _, path, marker, sev, cvss, text = result
            findings.append(wrap_finding(text, sev, cvss=cvss, cwe="CWE-538",
                owasp="A05:2021",
                remediation=f"Block public access to /{path} at the web server level.",
                evidence_marker=f"GET /{path} returned 200 with content matching marker"))
            matches.append({"path": path, "severity": sev})

    summary = (f"{len(_PATHS)} sensitive paths probed in {time.time() - _wallclock_start:.1f}s "
               f"with 16-thread pool; marker verification required")
    if suppressed:
        summary += f"; {len(suppressed)} SPA matches filtered as non-vulnerable"
    if _bailed:
        summary += f" — wall-clock bailed at {_WALLCLOCK_BUDGET}s"

    return vuln_response(tool="exposed_files", target=req.target,
        findings=findings, tested=len(_PATHS),
        what_checked=f"sensitive paths exposed publicly ({len(_PATHS)}-path AI-curated wordlist: .env, .git, backups, cloud creds, K8s, SSH, IDE files)",
        tests_summary=summary,
        raw_data={"exposed_files": {"matches": matches,
                                     "spa_mode": spa_mode,
                                     "suppressed_fps": suppressed,
                                     "wordlist_size": len(_PATHS),
                                     "wallclock_bailed": _bailed}})


def register(app):
    app.include_router(router)
