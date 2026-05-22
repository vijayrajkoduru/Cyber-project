"""Directory Enumeration — findings rules library.

State shape:
  found (list of dicts: {path, status, length, category?}),
  found_count (int),
  paths_probed (int),
  custom_404_detected (bool),
  category_counts (dict — secrets/git/admin/backup/config),
"""
import re

# Path patterns → category mapping (drives high-impact findings)
_CATEGORIES = {
    "secrets":   [r"\.env(\.|\$|/)", r"secrets?\.(json|yml|yaml)",
                  r"credentials?\.(json|txt|yml)", r"\.aws/", r"\.ssh/",
                  r"master\.key", r"private\.key", r"\.pem$"],
    "git":       [r"\.git/", r"\.svn/", r"\.hg/", r"\.bzr/"],
    "config":    [r"config\.(php|json|yaml|yml|xml|ini)",
                  r"web\.config$", r"wp-config\.php", r"appsettings\.json",
                  r"database\.(yml|conf)"],
    "admin":     [r"^admin/?$", r"administrator", r"wp-admin", r"phpmyadmin",
                  r"adminer", r"manage(r|ment)?$", r"console$", r"backend$",
                  r"dashboard"],
    "backup":    [r"backup", r"\.bak$", r"\.old$", r"\.swp$", r"\.orig$",
                  r"~$", r"\.tar\.gz$", r"\.zip$", r"\.sql$", r"\.dump$"],
    "ide":       [r"\.vscode/", r"\.idea/", r"\.DS_Store$", r"Thumbs\.db$"],
}


def _classify(path):
    p = path.lower()
    for cat, patterns in _CATEGORIES.items():
        for pat in patterns:
            if re.search(pat, p):
                return cat
    return None


def rule_secrets_exposed(s):
    found = [f for f in (s.get("found") or [])
              if f.get("category") == "secrets" and f.get("status") == 200]
    if not found: return None
    paths = ", ".join(f["path"] for f in found[:5])
    return {"name": f"Secret/credential files exposed ({len(found)})",
            "severity": "CRITICAL",
            "cwe": "CWE-200",
            "evidence": f"HTTP 200 on: {paths}",
            "remediation": "Block these paths at WAF/nginx immediately. Rotate any credentials exposed (treat as compromised). .env files and SSH keys in public web roots are the #1 source of mass-credential leaks."}


def rule_git_repo_exposed(s):
    found = [f for f in (s.get("found") or [])
              if f.get("category") == "git" and f.get("status") == 200]
    if not found: return None
    return {"name": f"Source-control directory exposed ({len(found)} path(s))",
            "severity": "HIGH",
            "cwe": "CWE-540",
            "evidence": f"Accessible: {', '.join(f['path'] for f in found[:3])}",
            "remediation": "Block /.git/, /.svn/, /.hg/ at nginx with `location ~ /\\.(git|svn|hg) { deny all; }`. Exposed .git/ allows full source-code extraction via git-dumper tools."}


def rule_config_files_exposed(s):
    found = [f for f in (s.get("found") or [])
              if f.get("category") == "config" and f.get("status") == 200]
    if not found: return None
    return {"name": f"Configuration files exposed ({len(found)})",
            "severity": "HIGH",
            "cwe": "CWE-200",
            "evidence": f"HTTP 200: {', '.join(f['path'] for f in found[:5])}",
            "remediation": "Configuration files often contain DB credentials, API keys, SMTP passwords. Move outside web root or block via webserver rules."}


def rule_admin_panel_found(s):
    found = [f for f in (s.get("found") or [])
              if f.get("category") == "admin" and f.get("status") in (200, 401, 403)]
    if not found: return None
    sample = "; ".join(f"{x['path']} ({x.get('status')})" for x in found[:5])
    return {"name": f"Admin panels discovered ({len(found)})",
            "severity": "MEDIUM",
            "cwe": "CWE-200",
            "evidence": f"Reachable: {sample}",
            "remediation": "Admin panels should be IP-restricted or VPN-only. Even with auth, exposure = brute-force surface + 0-day target."}


def rule_backup_files(s):
    found = [f for f in (s.get("found") or [])
              if f.get("category") == "backup" and f.get("status") == 200]
    if not found: return None
    return {"name": f"Backup files exposed ({len(found)})",
            "severity": "HIGH",
            "cwe": "CWE-530",
            "evidence": f"HTTP 200: {', '.join(f['path'] for f in found[:3])}",
            "remediation": "Backups in webroot leak full app code + DB. Move backups outside webroot. Block .bak/.old/.zip via WAF."}


def rule_ide_files_exposed(s):
    found = [f for f in (s.get("found") or [])
              if f.get("category") == "ide" and f.get("status") == 200]
    if not found: return None
    return {"name": f"IDE/editor metadata exposed ({len(found)})",
            "severity": "LOW",
            "cwe": "CWE-200",
            "evidence": f"Found: {', '.join(f['path'] for f in found[:3])}",
            "remediation": "Add .vscode/, .idea/, .DS_Store to .gitignore + block at nginx. Leaks workspace structure + sometimes auth tokens."}


def rule_total_count(s):
    n = s.get("found_count") or 0
    if n == 0: return None
    probed = s.get("paths_probed") or 0
    return {"name": f"{n} accessible path(s) discovered",
            "severity": "INFO",
            "evidence": f"{n} of {probed} probed paths returned 2xx/3xx/4xx"}


def rule_no_paths_found(s):
    if (s.get("found_count") or 0) > 0: return None
    if (s.get("paths_probed") or 0) == 0: return None
    return {"name": "Directory enumeration found no accessible paths",
            "severity": "POSITIVE",
            "evidence": "All probed paths returned 404 — strong content security"}


def rule_custom_404(s):
    if not s.get("custom_404_detected"): return None
    return {"name": "Custom 404 page detected — results may include false-positives",
            "severity": "INFO",
            "evidence": "Server returns 200 OK with custom error page instead of 404",
            "remediation": "Manually verify each finding. Custom 404 (or SPA index.html catch-all) inflates false-positive rate. Configure server to return real 404 status code for missing paths."}


DIRECTORY_FINDING_RULES = [
    rule_secrets_exposed,
    rule_git_repo_exposed,
    rule_config_files_exposed,
    rule_admin_panel_found,
    rule_backup_files,
    rule_ide_files_exposed,
    rule_total_count,
    rule_no_paths_found,
    rule_custom_404,
]


def classify_path(path):
    """Public helper — classify a path into a category."""
    return _classify(path)
