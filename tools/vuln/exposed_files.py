"""Exposed Sensitive Files — 30+ paths with SPA-baseline FP suppression.

A SPA (React/Angular/Vue/Next) returns 200 OK + the SPA shell HTML for
ANY path, including /.env, /.git/config, etc. Without a baseline check
these all match generic markers and produce false-positive CRITICALs.
"""
import hashlib
import re
import secrets
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_get, wrap_finding, standard_response)
router = APIRouter()

_PATHS = [
    (".env",                r"[A-Z_]+\s*=\s*\S",            "CRITICAL","9.1",".env exposes environment variables"),
    (".env.local",          r"[A-Z_]+\s*=\s*\S",            "CRITICAL","9.1",".env.local exposed"),
    (".env.production",     r"[A-Z_]+\s*=\s*\S",            "CRITICAL","9.8",".env.production exposed — prod credentials leaked"),
    (".env.backup",         r"[A-Z_]+\s*=\s*\S",            "CRITICAL","9.1",".env.backup exposed"),
    (".git/config",         r"\[core\]|\[remote",           "HIGH",    "7.5",".git/config exposed — repo can be reconstructed"),
    (".git/HEAD",           r"^ref:\s+",                    "HIGH",    "7.5",".git/HEAD exposed — .git directory leaked"),
    (".git/index",          r"DIRC",                        "HIGH",    "7.5",".git/index exposed"),
    (".svn/entries",        r"svn:|\d+\n",                  "MEDIUM",  "5.3",".svn directory exposed"),
    ("wp-config.php.bak",   r"DB_PASSWORD|DB_USER",         "CRITICAL","9.8","wp-config.php.bak — WordPress DB credentials leaked"),
    ("wp-config.php~",      r"DB_PASSWORD|DB_USER",         "CRITICAL","9.8","wp-config.php~ exposed"),
    ("config.php.bak",      r"\$db|\$pass|\$secret",        "HIGH",    "8.1","PHP config backup exposed"),
    ("backup.sql",          r"CREATE TABLE|INSERT INTO",    "CRITICAL","9.1","Database backup (.sql) exposed publicly"),
    ("db.sql",              r"CREATE TABLE|INSERT INTO",    "CRITICAL","9.1","Database dump exposed"),
    ("database.sql",        r"CREATE TABLE|INSERT INTO",    "CRITICAL","9.1","database.sql exposed"),
    ("dump.sql",            r"CREATE TABLE|INSERT INTO",    "CRITICAL","9.1","dump.sql exposed"),
    ("composer.lock",       r'"packages"',                  "LOW",     "3.1","composer.lock exposed — reveals PHP deps"),
    ("package-lock.json",   r'"lockfileVersion"',           "LOW",     "3.1","package-lock.json exposed — reveals JS deps"),
    (".aws/credentials",    r"aws_access_key_id|\[default\]","CRITICAL","9.8","AWS credentials exposed"),
    (".ssh/id_rsa",         r"-----BEGIN .*PRIVATE KEY-----","CRITICAL","9.8","SSH private key exposed"),
    (".ssh/authorized_keys",r"ssh-rsa|ssh-ed25519",         "HIGH",    "8.1","SSH authorized_keys exposed"),
    ("phpinfo.php",         r"<title>phpinfo\(\)",          "MEDIUM",  "5.3","phpinfo() exposed"),
    ("info.php",            r"<title>phpinfo\(\)",          "MEDIUM",  "5.3","info.php = phpinfo() leaked"),
    ("server-status",       r"<title>Apache Status",        "MEDIUM",  "5.3","Apache server-status exposed"),
    (".htpasswd",           r":\$\w+\$",                    "CRITICAL","9.1",".htpasswd exposed — password hashes leaked"),

    ("ftp/legal.md",        r"MIT License|legal|copyright",       "LOW",     "3.1","/ftp/legal.md exposed — directory listing potentially open"),
    ("ftp/package.json.bak",r'"name"|"version"',                  "MEDIUM",  "5.3","/ftp/package.json.bak exposed — reveals app stack"),
    ("encryptionkeys/",     r"-----BEGIN|<title>Index of|premium\.key", "HIGH",  "8.1","/encryptionkeys/ directory exposed — crypto material leaked"),
    ("metrics",             r"# HELP|# TYPE|process_cpu",          "MEDIUM",  "5.3","/metrics endpoint exposed publicly"),
    ("support/logs/",       r"<title>Index of|access\.log|error\.log","MEDIUM","5.3","/support/logs/ directory listing exposed"),
    (".DS_Store",           r"\x00\x00\x00\x01Bud1",            "LOW",     "3.7",".DS_Store exposed — reveals directory structure"),
    ("server-status?auto",  r"Total Accesses|BusyWorkers",         "MEDIUM",  "5.3","/server-status?auto exposed — Apache stats public"),
]


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


@router.post("/api/scan/exposed_files")
async def scan_exposed_files(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")

    # SPA-shell baseline: a guaranteed-nonexistent path tells us what the
    # site returns for "404-equivalent". On a static / non-SPA site this
    # comes back as a real 404 (different fingerprint). On a SPA it returns
    # the same 200 shell as any other unknown path — any match below that
    # equals the baseline is the SPA shell, not a real file.
    canary_path = "/_vl_canary_" + secrets.token_hex(8) + ".bogus"
    canary = safe_get(f"{base}{canary_path}", req=req, allow_redirects=False, timeout=8)
    baseline_fp = _fingerprint(canary)
    spa_mode = canary is not None and canary.status_code == 200

    findings, matches, suppressed = [], [], []
    for path, marker, sev, cvss, text in _PATHS:
        r = safe_get(f"{base}/{path}", req=req, allow_redirects=False, timeout=8)
        if r is None or r.status_code != 200:
            continue
        # SPA-baseline gate — if the response is structurally identical to
        # the bogus-path response, we're looking at the SPA shell, not the
        # real file. Skip.
        probe_fp = _fingerprint(r)
        if spa_mode and probe_fp == baseline_fp:
            suppressed.append({"path": path, "reason": "matches_spa_shell"})
            continue
        if not _match((r.text or "")[:4000], marker):
            continue
        findings.append(wrap_finding(text, sev, cvss=cvss, cwe="CWE-538",
            owasp="A05:2021",
            remediation=f"Block public access to /{path} at the web server level.",
            evidence_marker=f"GET /{path} returned 200 with content matching marker"))
        matches.append({"path": path, "severity": sev})

    summary = f"{len(_PATHS)} sensitive paths probed; marker verification required"
    if suppressed:
        summary += f"; SPA-baseline suppressed {len(suppressed)} FP(s)"

    return standard_response(tool="exposed_files", target=req.target,
        findings=findings, tests_performed=len(_PATHS),
        tests_summary=summary,
        raw_data={"exposed_files": {"matches": matches,
                                     "spa_mode": spa_mode,
                                     "suppressed_fps": suppressed}})


def register(app):
    app.include_router(router)
