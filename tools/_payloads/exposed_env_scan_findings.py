"""exposed_env_scan - finding rules (VL-METHOD aware).

Rules read state populated by ExposedEnvScan's 7-stage flow:
  - methodology_findings : list of secret matches (with confidence + privilege)
  - target_base          : normalized URL probed
  - fingerprint          : dict {server, powered_by, framework, ...}
  - quick_probe_attempts : top-8 paths tried
  - quick_probe_hits     : how many returned real content
  - env_deep_paths       : total deep paths probed
  - chain_next           : list of follow-up scanner names

Severity derives from CONFIRMED + secret type:
  CONFIRMED aws_credentials      -> CRITICAL CVSS 9.8
  CONFIRMED db_connection_string -> CRITICAL CVSS 9.4
  CONFIRMED ssh_private_key      -> CRITICAL CVSS 9.4
  CONFIRMED jwt_secret           -> HIGH     CVSS 8.1
  CONFIRMED generic_password     -> MEDIUM   CVSS 6.5
  SUSPECTED any                  -> LOW      CVSS 3.7
"""


INTEL_FIELDS = [
    ("Target",               "target_base"),
    ("Server Fingerprint",   "fingerprint"),
    ("Paths probed",         "quick_probe_attempts"),
    ("Paths with content",   "quick_probe_hits"),
    ("Deep paths probed",    "env_deep_paths"),
    ("Stage timings (ms)",   "stage_timings"),
    ("Stage errors",         "stage_errors"),
    ("Chain ID",             "chain_id"),
]


# ── helpers ──────────────────────────────────────────────────────────


def _findings_by_severity_and_type(s):
    """Group methodology_findings by (severity, secret-match-type)."""
    out = {
        "aws_credentials":      {"CONFIRMED": [], "SUSPECTED": []},
        "db_connection_string": {"CONFIRMED": [], "SUSPECTED": []},
        "jwt_secret":           {"CONFIRMED": [], "SUSPECTED": []},
        "ssh_private_key":      {"CONFIRMED": [], "SUSPECTED": []},
        "generic_password":     {"CONFIRMED": [], "SUSPECTED": []},
        "other":                {"CONFIRMED": [], "SUSPECTED": []},
    }
    for f in (s.get("methodology_findings") or []):
        mt = f.get("match_type", "other")
        conf = f.get("confidence", "SUSPECTED")
        if mt not in out:
            mt = "other"
        if conf not in ("CONFIRMED", "SUSPECTED"):
            conf = "SUSPECTED"
        out[mt][conf].append(f)
    return out


def _paths_summary(findings, limit=5):
    seen = []
    for f in findings:
        p = f.get("file_path") or ""
        if p and p not in seen:
            seen.append(p)
        if len(seen) >= limit:
            break
    return ", ".join(seen)


# ── rules ────────────────────────────────────────────────────────────


def rule_target_unreachable(s):
    sr = s.get("skipped_reason") or ""
    if "target HTTP not reachable" not in sr:
        return None
    return {
        "name": "Target HTTP endpoint not reachable - cannot scan for exposed credentials",
        "severity": "INFO",
        "evidence": sr or "Base URL did not respond to a probe request.",
        "remediation": ("Verify the target URL is reachable from the scanner host "
                        "(DNS, firewall, TLS). Re-run the scan once the application "
                        "responds so we can verify no config / credential files are "
                        "exposed over HTTP."),
        "cwe": "CWE-1006",
    }


def rule_input_missing(s):
    # Included for pattern consistency with other VL-METHOD scanners even
    # though this scanner needs only a target URL.
    sr = s.get("skipped_reason") or ""
    if "form_url not supplied" not in sr:
        return None
    return {
        "name": "Required input not supplied - exposed credential scan skipped",
        "severity": "INFO",
        "evidence": sr,
        "remediation": ("Supply the target base URL on the request body so the "
                        "scanner can enumerate the standard credential-leak paths."),
        "cwe": "CWE-1006",
    }


def rule_positive_clean(s):
    """Zero secrets across all stages + at least 5 paths probed + target was
    reachable. Honest POSITIVE: actually swept the standard leak surface."""
    if (s.get("methodology_total") or 0) > 0:
        return None
    if "target HTTP not reachable" in (s.get("skipped_reason") or ""):
        return None
    if not s.get("target_base"):
        return None
    probed = int(s.get("quick_probe_attempts") or 0) + int(s.get("env_deep_paths") or 0)
    if probed < 5:
        return None
    fp = s.get("fingerprint") or {}
    return {
        "name": "No exposed configuration / credential files detected",
        "severity": "POSITIVE",
        "evidence": (f"Probed {probed} common credential-leak paths (.env, .git/config, "
                     f".htpasswd, wp-config.php, credentials.json, .aws/credentials, "
                     f"backup.sql + extended list); none returned credential content. "
                     f"Server fingerprint: {fp.get('server') or 'unknown'} / "
                     f"{fp.get('framework') or 'unknown framework'}."),
        "remediation": ("Continue blocking serving of dot-files and config files at "
                        "the web layer (nginx `location ~ /\\.` deny; Apache `<FilesMatch "
                        "\"^\\.\">` Require all denied). Add CI checks that fail builds "
                        "if .env, .git, or *.sql land under the document root."),
        "cwe": "CWE-538",
        "owasp": "A05:2021",
    }


def rule_confirmed_aws_creds(s):
    g = _findings_by_severity_and_type(s)
    hits = g["aws_credentials"]["CONFIRMED"]
    if not hits:
        return None
    return {
        "name": f"CONFIRMED AWS credentials exposed via HTTP ({len(hits)} match)",
        "severity": "CRITICAL", "cvss": "9.8",
        "cwe": "CWE-798", "owasp": "A05:2021",
        "evidence": ("Live AWS access key(s) discovered in publicly-served file(s). "
                     "Each finding was re-fetched (httpx second request) to confirm "
                     "stability and structurally validated (AKIA + 16 chars). "
                     f"Files: {_paths_summary(hits)}. Privilege class: cloud_root."),
        "remediation": ("CRITICAL - rotate the leaked AWS access key in IAM immediately, "
                        "then revoke the old key. Audit CloudTrail for any unauthorized "
                        "API calls using the leaked key (treat the account as "
                        "potentially compromised). Remove the file from the docroot, "
                        "purge it from git history (git filter-repo / BFG), and add a "
                        "web-server rule blocking dot-files + *.json / *.yml at the "
                        "perimeter. Move credentials to AWS Secrets Manager or "
                        "environment variables loaded outside the served directory."),
    }


def rule_confirmed_db_creds(s):
    g = _findings_by_severity_and_type(s)
    hits = g["db_connection_string"]["CONFIRMED"]
    if not hits:
        return None
    return {
        "name": f"CONFIRMED database connection string exposed via HTTP ({len(hits)} match)",
        "severity": "CRITICAL", "cvss": "9.4",
        "cwe": "CWE-798", "owasp": "A05:2021",
        "evidence": ("Database URL containing embedded user:pass@host credentials "
                     "discovered in a publicly-served file. Structurally validated "
                     "(scheme://user:pass@host/db). Re-fetched to confirm stable. "
                     f"Files: {_paths_summary(hits)}. Privilege class: database_owner."),
        "remediation": ("CRITICAL - rotate the database password immediately. Audit "
                        "DB logs for unauthorized queries / dumps. Move the connection "
                        "string to environment variables loaded from a file OUTSIDE "
                        "the document root (e.g. /etc/app/secrets.env). Block "
                        "config.* / database.yml / *.env at the web-server layer. "
                        "Verify the DB is not directly reachable from the internet."),
    }


def rule_confirmed_jwt_secret(s):
    g = _findings_by_severity_and_type(s)
    hits = g["jwt_secret"]["CONFIRMED"]
    if not hits:
        return None
    return {
        "name": f"CONFIRMED JWT signing secret exposed via HTTP ({len(hits)} match)",
        "severity": "HIGH", "cvss": "8.1",
        "cwe": "CWE-798", "owasp": "A02:2021",
        "evidence": ("JWT signing secret discovered in a publicly-served file. "
                     "Anyone with this secret can forge valid auth tokens for ANY "
                     "user of the application (full authentication bypass). "
                     f"Files: {_paths_summary(hits)}. Privilege class: auth_bypass_capable."),
        "remediation": ("Rotate the JWT signing secret immediately and invalidate all "
                        "outstanding tokens (force re-login). Move the secret to a "
                        "secrets manager / env var loaded outside the docroot. Audit "
                        "auth logs for token-forge symptoms (tokens with unusual "
                        "claims, iat far in the past, etc.). Consider switching to "
                        "RS256 + key-pair rotation for higher assurance."),
    }


def rule_confirmed_ssh_key(s):
    g = _findings_by_severity_and_type(s)
    hits = g["ssh_private_key"]["CONFIRMED"]
    if not hits:
        return None
    return {
        "name": f"CONFIRMED SSH private key exposed via HTTP ({len(hits)} match)",
        "severity": "CRITICAL", "cvss": "9.4",
        "cwe": "CWE-798", "owasp": "A05:2021",
        "evidence": ("Private key material (BEGIN ... PRIVATE KEY block) exposed in "
                     "a publicly-served file. Whoever downloads this key can "
                     "authenticate to whatever the corresponding public key "
                     f"authorizes. Files: {_paths_summary(hits)}. Privilege class: key_material."),
        "remediation": ("CRITICAL - immediately revoke the corresponding public key "
                        "from all hosts it authorizes (remove from "
                        "~/.ssh/authorized_keys, AWS EC2 key-pairs, GitHub deploy "
                        "keys, etc.). Generate a fresh keypair. Remove the leaked "
                        "key file from the docroot AND from git history. Audit "
                        "auth.log on every host that trusted the old key for "
                        "unauthorized SSH sessions."),
    }


def rule_confirmed_generic_credential(s):
    g = _findings_by_severity_and_type(s)
    hits = g["generic_password"]["CONFIRMED"]
    if not hits:
        return None
    return {
        "name": f"CONFIRMED credential / password exposed via HTTP ({len(hits)} match)",
        "severity": "MEDIUM", "cvss": "6.5",
        "cwe": "CWE-798", "owasp": "A05:2021",
        "evidence": ("Password / API-token / secret assignment discovered in a "
                     "publicly-served file. Structurally a credential pair (key + "
                     "value, length >= 8). Re-fetched to confirm stable. "
                     f"Files: {_paths_summary(hits)}. Privilege class: credential."),
        "remediation": ("Rotate the leaked credential. Move it into a secrets store / "
                        "env var loaded outside the docroot. Add web-server rule "
                        "denying dot-files + config.* / *.yml / *.json. Add a CI "
                        "secret-scanner (gitleaks / trufflehog) to prevent regressions."),
    }


def rule_suspected_secret(s):
    g = _findings_by_severity_and_type(s)
    suspected = []
    for mt in g.values():
        suspected.extend(mt["SUSPECTED"])
    if not suspected:
        return None
    return {
        "name": f"SUSPECTED exposed secret ({len(suspected)} match - manual verification needed)",
        "severity": "LOW", "cvss": "3.7",
        "cwe": "CWE-798", "owasp": "A05:2021",
        "evidence": ("Pattern-matched secret(s) found in served files but structural "
                     "validation failed (e.g. AWS key wrong length, JWT secret <= 16 "
                     "chars, DB URL missing user:pass@host). Could be a placeholder, "
                     "example value, or genuine misformatted secret. "
                     f"Files: {_paths_summary(suspected)}."),
        "remediation": ("Manually open the URL(s) and inspect. If real secrets, treat "
                        "as the corresponding CONFIRMED class (rotate + remove + "
                        "audit). If placeholder/example, remove from docroot anyway "
                        "to avoid confusion and to reduce the attack surface."),
    }


def rule_chain_handoff(s):
    chain_next = s.get("chain_next") or []
    if not chain_next:
        return None
    return {
        "name": "Cross-scanner chain handoff suggested",
        "severity": "INFO",
        "evidence": ("Confirmed exposed credentials enable downstream scanners: " +
                     ", ".join(chain_next)),
        "remediation": ("Re-run scan with chain_id propagation to automatically "
                        "follow up with: " + ", ".join(chain_next) + ". "
                        "These will inherit the captured credentials via the "
                        "VL-METHOD chaining engine."),
        "cwe": "CWE-1006",
    }


EXPOSED_ENV_SCAN_FINDING_RULES = [
    rule_target_unreachable,
    rule_input_missing,
    rule_positive_clean,
    rule_confirmed_aws_creds,
    rule_confirmed_db_creds,
    rule_confirmed_jwt_secret,
    rule_confirmed_ssh_key,
    rule_confirmed_generic_credential,
    rule_suspected_secret,
    rule_chain_handoff,
]
