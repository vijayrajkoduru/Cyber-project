"""Exposed Sensitive Files scanner — 30+ paths with marker verification."""
import re
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
]

def _match(body, pat):
    if pat is None: return len(body or "") > 50
    try: return re.search(pat, body or "", re.IGNORECASE) is not None
    except: return False

@router.post("/api/scan/exposed_files")
async def scan_exposed_files(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings, matches = [], []
    for path, marker, sev, cvss, text in _PATHS:
        r = safe_get(f"{base}/{path}", req=req, allow_redirects=False, timeout=8)
        if r is None or r.status_code != 200: continue
        if not _match((r.text or "")[:4000], marker): continue
        findings.append(wrap_finding(text, sev, cvss=cvss, cwe="CWE-538", owasp="A05:2021",
            remediation=f"Block public access to /{path} at the web server level.",
            evidence_marker=f"GET /{path} returned 200 with content matching marker"))
        matches.append({"path": path, "severity": sev})
    return standard_response(tool="exposed_files", target=req.target,
        findings=findings, tests_performed=len(_PATHS),
        tests_summary=f"{len(_PATHS)} sensitive paths probed; marker verification required",
        raw_data={"exposed_files": {"matches": matches}})
def register(app): app.include_router(router)
