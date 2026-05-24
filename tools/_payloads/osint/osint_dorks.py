"""osint_dorks — 50 Google/Bing/DDG dorks for OSINT discovery.

Generated 2026-05-24 — handcrafted (AI dual-use refusal on dorks).
Refresh cadence: quarterly. Source: SANS / TrustedSec OSINT cheatsheets +
Google Hacking Database (Exploit-DB) condensed to highest-signal queries.

Format: each entry is a query template with {target} substitution slot.
The scanner runs each query against DDG (no rate-limit) and flags hits.
"""

OSINT_DORKS = [
    # File type discovery
    'site:{target} filetype:pdf',
    'site:{target} filetype:doc OR filetype:docx',
    'site:{target} filetype:xls OR filetype:xlsx',
    'site:{target} filetype:ppt OR filetype:pptx',
    'site:{target} filetype:txt OR filetype:csv',
    'site:{target} filetype:sql OR filetype:db',
    'site:{target} filetype:log',
    'site:{target} filetype:bak OR filetype:old OR filetype:orig',
    'site:{target} filetype:env OR filetype:ini OR filetype:conf',
    'site:{target} filetype:yml OR filetype:yaml',

    # Sensitive paths
    'site:{target} inurl:admin',
    'site:{target} inurl:login',
    'site:{target} inurl:dashboard',
    'site:{target} inurl:wp-admin',
    'site:{target} inurl:phpmyadmin',
    'site:{target} inurl:.git',
    'site:{target} inurl:backup',
    'site:{target} inurl:test',
    'site:{target} inurl:staging',
    'site:{target} inurl:dev',

    # Information disclosure
    'site:{target} intitle:"index of"',
    'site:{target} intitle:"index of /"',
    'site:{target} "phpinfo"',
    'site:{target} "stack trace"',
    'site:{target} "fatal error"',
    'site:{target} "warning: mysql"',
    'site:{target} "DB_PASSWORD"',
    'site:{target} "api_key"',
    'site:{target} "secret_key"',
    'site:{target} "private_key"',

    # Credentials / leaks
    '"{target}" "password" filetype:txt',
    '"{target}" "BEGIN RSA PRIVATE KEY"',
    '"{target}" "BEGIN OPENSSH PRIVATE KEY"',
    '"{target}" intext:"@gmail.com" OR intext:"@outlook.com"',
    '"{target}" intext:"AKIA" -github.com',
    '"{target}" "aws_secret_access_key"',
    '"{target}" "ghp_" OR "github_pat_"',
    '"{target}" "xoxb-" OR "xoxp-"',
    '"{target}" "sk-" -openai.com',

    # Third-party surface
    'site:pastebin.com "{target}"',
    'site:gist.github.com "{target}"',
    'site:trello.com "{target}"',
    'site:s3.amazonaws.com "{target}"',
    'site:blob.core.windows.net "{target}"',
    'site:storage.googleapis.com "{target}"',
    'site:linkedin.com/in "{target}"',
    'site:facebook.com "{target}"',
    'site:reddit.com "{target}"',
    'site:stackoverflow.com "{target}"',
    'site:medium.com "{target}"',
]

# Severity hint per dork category — used by the scanner to assign finding severity
DORK_SEVERITY = {
    # CRITICAL — direct credential/key exposure
    'AKIA': 'CRITICAL', 'BEGIN RSA': 'CRITICAL', 'BEGIN OPENSSH': 'CRITICAL',
    'aws_secret': 'CRITICAL', 'api_key': 'HIGH', 'secret_key': 'HIGH',
    'DB_PASSWORD': 'CRITICAL', 'private_key': 'HIGH', 'ghp_': 'CRITICAL',
    'xoxb-': 'CRITICAL', 'sk-': 'HIGH',
    # HIGH — sensitive file/path exposure
    'filetype:sql': 'HIGH', 'filetype:env': 'HIGH', 'filetype:log': 'HIGH',
    '.git': 'HIGH', 'phpinfo': 'HIGH', 'stack trace': 'MEDIUM',
    # MEDIUM — admin surface
    'inurl:admin': 'MEDIUM', 'inurl:wp-admin': 'MEDIUM',
    'inurl:phpmyadmin': 'HIGH', 'inurl:dashboard': 'MEDIUM',
    'index of': 'MEDIUM',
    # LOW — informational
    'filetype:pdf': 'LOW', 'filetype:doc': 'LOW',
    'pastebin.com': 'MEDIUM', 's3.amazonaws.com': 'MEDIUM',
}


def severity_for(dork: str) -> str:
    """Pick severity based on dork keywords. Falls back to LOW."""
    for k, sev in DORK_SEVERITY.items():
        if k in dork:
            return sev
    return "LOW"
