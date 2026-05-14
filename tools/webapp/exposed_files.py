"""Exposed sensitive files scanner.

Workflow (no false positives on SPAs that always 200):
  1. Probe a random path to establish the site's 404 baseline.
  2. For each candidate path, require:
       - Status 200/206
       - Response differs meaningfully from the baseline
       - Content matches the file's signature pattern

Only signature-matched results are reported.
"""
import re
import uuid
from fastapi import APIRouter, Depends

from tools._shared import (
    ScanRequest, verify_scan_quota, web_url,
    safe_get, wrap_finding, standard_response,
)

router = APIRouter()


SIGNATURES = [
    (".env", "CRITICAL",
     "Environment file exposes application secrets",
     re.compile(r"(?im)^\s*[A-Z_][A-Z0-9_]*\s*=\s*\S"),
     "Move .env outside the web root; deny access at the server level."),
    (".git/config", "CRITICAL",
     "Git repository config exposed — source may be downloadable",
     re.compile(r"\[core\]|\[remote\b", re.I),
     "Block access to /.git/ at the web server."),
    (".git/HEAD", "CRITICAL",
     "Git HEAD pointer exposed — repo likely reconstructable",
     re.compile(r"ref: refs/", re.I),
     "Block access to /.git/ at the web server."),
    (".svn/entries", "HIGH",
     "Subversion metadata exposed",
     re.compile(r"^\d+|svn:", re.M),
     "Block access to /.svn/ at the web server."),
    ("backup.zip", "HIGH",
     "Backup archive (zip) accessible",
     re.compile(rb"^PK\x03\x04"),
     "Remove backup archives from the web root."),
    ("backup.tar.gz", "HIGH",
     "Backup archive (tar.gz) accessible",
     re.compile(rb"^\x1f\x8b"),
     "Remove backup archives from the web root."),
    ("backup.sql", "HIGH",
     "SQL database dump exposed",
     re.compile(r"(?i)CREATE TABLE|INSERT INTO|DROP TABLE"),
     "Remove SQL dumps from the web root."),
    ("database.sql", "HIGH",
     "SQL database dump exposed",
     re.compile(r"(?i)CREATE TABLE|INSERT INTO|DROP TABLE"),
     "Remove SQL dumps from the web root."),
    ("dump.sql", "HIGH",
     "SQL database dump exposed",
     re.compile(r"(?i)CREATE TABLE|INSERT INTO|DROP TABLE"),
     "Remove SQL dumps from the web root."),
    ("phpinfo.php", "HIGH",
     "phpinfo() output exposes server configuration",
     re.compile(r"PHP Version|phpinfo\(\)", re.I),
     "Remove phpinfo.php from the web root."),
    ("server-status", "MEDIUM",
     "Apache mod_status exposes internal server state",
     re.compile(r"Apache Server Status", re.I),
     "Disable mod_status or restrict to localhost."),
    ("server-info", "MEDIUM",
     "Apache mod_info exposes module configuration",
     re.compile(r"Apache Server Information", re.I),
     "Disable mod_info."),
    (".htaccess", "MEDIUM",
     ".htaccess file directly accessible",
     re.compile(r"RewriteEngine|RewriteRule|AuthType|Require", re.I),
     "Deny direct access to .htaccess files in Apache config."),
    ("wp-config.php.bak", "CRITICAL",
     "WordPress config backup — DB credentials likely leaked",
     re.compile(r"DB_NAME|DB_USER|DB_PASSWORD", re.I),
     "Remove backup files from the web root."),
    ("wp-config.php~", "CRITICAL",
     "WordPress config editor-backup exposed",
     re.compile(r"DB_NAME|DB_USER|DB_PASSWORD", re.I),
     "Remove editor backup files (vim/emacs)."),
    ("config.php.bak", "HIGH",
     "PHP config backup exposed",
     re.compile(r"<\?php|define\(", re.I),
     "Remove backup files."),
    (".DS_Store", "LOW",
     "macOS metadata file exposes directory listing",
     re.compile(rb"Bud1"),
     "Remove .DS_Store from deploys; add to .gitignore."),
]


def _matches(sig, content_bytes, content_text):
    try:
        if sig.search(content_bytes):
            return True
    except TypeError:
        pass
    try:
        if sig.search(content_text):
            return True
    except TypeError:
        pass
    return False


@router.post("/api/scan/exposed_files")
async def scan_exposed_files(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    tests_count = 0
    raw_results = []

    # Step 1 — establish baseline using a random non-existent path
    baseline_path = f"/{uuid.uuid4().hex}/notreal_baseline.txt"
    baseline = safe_get(base + baseline_path, req=req, allow_redirects=False)
    if baseline is None:
        return standard_response(
            tool="exposed_files", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Could not reach {base}",
        )
    baseline_status = baseline.status_code
    baseline_len = len(baseline.content)

    # Step 2 — probe each candidate
    for path, sev, desc, sig, remediation in SIGNATURES:
        tests_count += 1
        url = f"{base}/{path}"
        r = safe_get(url, req=req, allow_redirects=False)
        if r is None:
            continue
        if r.status_code not in (200, 206):
            continue
        # Differ-from-baseline check (catches SPAs)
        if r.status_code == baseline_status and abs(len(r.content) - baseline_len) < 64:
            continue
        # Signature check
        try:
            text = r.text
        except Exception:
            text = ""
        if not _matches(sig, r.content, text):
            continue

        findings.append(wrap_finding(
            f"{desc} ({path})",
            sev, cwe="CWE-538", owasp="A01:2021",
            evidence_marker=f"GET {url} -> {r.status_code}, {len(r.content)}B, signature matched",
            remediation=remediation,
            tests_performed=1,
        ))
        raw_results.append({
            "path": path, "status": r.status_code,
            "length": len(r.content), "severity": sev,
        })

    return standard_response(
        tool="exposed_files", target=req.target, findings=findings,
        tests_performed=tests_count,
        tests_summary=f"Probed {tests_count} sensitive paths against {base}",
        raw_data={
            "exposed_files": {
                "baseline_status": baseline_status,
                "baseline_length": baseline_len,
                "matches": raw_results,
            }
        },
    )


def register(app):
    app.include_router(router)
