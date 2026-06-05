"""git_secrets_scan - finding rules (VL-METHOD aware).

Reads state keys populated by GitSecretsScan's 7-stage flow:
  - methodology_findings  : list of verified secrets with confidence + privilege
  - fingerprint           : repo info (head_commit, file_count, remote_url)
  - gitleaks_missing      : bool, true when gitleaks binary not on PATH
  - quick_probe_attempts  : int, files scanned in HEAD regex sweep
  - quick_probe_hits      : int, regex matches found in HEAD sweep
  - git_deep_secrets      : int, total secrets found in deep stage
  - chain_next            : list of follow-up scanner names

Severity derives from confidence + privilege_level combination:
  CONFIRMED cloud_root    -> CRITICAL  CVSS 9.8
  CONFIRMED key_material  -> CRITICAL  CVSS 9.4
  CONFIRMED service_token -> HIGH      CVSS 8.1
  CONFIRMED credential    -> MEDIUM    CVSS 6.5
  SUSPECTED any           -> LOW       CVSS 3.7
"""


INTEL_FIELDS = [
    ("Repository Info",     "fingerprint"),
    ("Files scanned",       "quick_probe_attempts"),
    ("Secrets found",       "quick_probe_hits"),
    ("Deep scan secrets",   "git_deep_secrets"),
    ("Stage timings (ms)",  "stage_timings"),
    ("Stage errors",        "stage_errors"),
    ("Chain ID",            "chain_id"),
]


def rule_input_missing(s):
    reason = s.get("skipped_reason") or ""
    if "repo_url or local_path" not in reason:
        return None
    return {
        "name": "Git secret scan skipped - no repository supplied",
        "severity": "INFO",
        "evidence": (f"Pre-flight failed: {reason}. Provide options.repo_url "
                     "(public https/git URL) OR options.local_path (path to "
                     "an already-cloned repo with .git/ directory) to run."),
        "remediation": ("Re-submit the scan with options.repo_url pointing at a "
                        "git repository you own, or options.local_path pointing "
                        "at a local working tree."),
        "cwe": "CWE-1006",
    }


def rule_gitleaks_missing(s):
    if not s.get("gitleaks_missing"):
        return None
    return {
        "name": "gitleaks binary not installed - using pure-Python fallback",
        "severity": "INFO",
        "evidence": ("gitleaks binary was not found on PATH. The scanner fell "
                     "back to a pure-Python regex sweep that only covers ~5 "
                     "top secret patterns (AWS keys, GitHub tokens, private "
                     "keys, Slack tokens, generic password=...). gitleaks "
                     "ships hundreds of curated rules covering Stripe, GCP, "
                     "Azure, Twilio, JWT, npm tokens, etc."),
        "remediation": ("Install gitleaks for deeper detection: "
                        "`curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/"
                        "gitleaks_linux_x64.tar.gz | tar -xz -C /usr/local/bin gitleaks` "
                        "(Linux) or `brew install gitleaks` (macOS). Re-run "
                        "the scan after install."),
        "cwe": "CWE-1006",
    }


def _findings_by_severity_and_type(s):
    """Group methodology_findings by (confidence, privilege_level).
    Returns dict with keys: cloud_root, key_material, service_token,
    credential, suspected. Values are lists of finding dicts."""
    out = {
        "cloud_root": [],
        "key_material": [],
        "service_token": [],
        "credential": [],
        "suspected": [],
    }
    for f in (s.get("methodology_findings") or []):
        conf = f.get("confidence", "SUSPECTED")
        priv = f.get("privilege_level", "unknown")
        if conf == "CONFIRMED":
            if priv == "cloud_root":
                out["cloud_root"].append(f)
            elif priv == "key_material":
                out["key_material"].append(f)
            elif priv == "service_token":
                out["service_token"].append(f)
            elif priv == "credential":
                out["credential"].append(f)
            else:
                out["suspected"].append(f)
        else:
            out["suspected"].append(f)
    return out


def _fingerprint_ok(s) -> bool:
    """True if fingerprint stage produced a real repo snapshot."""
    fp = s.get("fingerprint") or {}
    return bool(fp.get("head_commit") or fp.get("file_count"))


def rule_positive_clean(s):
    """Zero secrets across all stages + fingerprint succeeded -> POSITIVE."""
    if s.get("methodology_total", 0) > 0:
        return None
    if (s.get("quick_probe_hits") or 0) > 0:
        return None
    if (s.get("git_deep_secrets") or 0) > 0:
        return None
    if not _fingerprint_ok(s):
        return None
    if s.get("skipped_reason"):
        return None
    fp = s.get("fingerprint") or {}
    files = fp.get("file_count") or s.get("quick_probe_attempts", 0)
    return {
        "name": "No leaked secrets detected in repository",
        "severity": "POSITIVE",
        "evidence": (f"Scanned {files} tracked files at HEAD ({fp.get('head_commit', 'unknown')[:12]}) "
                     "with regex + gitleaks; zero high-confidence credential, "
                     "API token, private key, or cloud access key matches."),
        "remediation": ("Continue current secret-handling practice. Consider "
                        "adding a pre-commit hook (gitleaks protect --staged) "
                        "to keep this clean going forward."),
        "cwe": "CWE-798",
        "owasp": "A07:2021",
    }


def rule_confirmed_cloud_creds(s):
    g = _findings_by_severity_and_type(s)
    if not g["cloud_root"]:
        return None
    sample = ", ".join(f.get("file", "?") for f in g["cloud_root"][:3])
    return {
        "name": f"CONFIRMED leaked cloud credentials ({len(g['cloud_root'])} secret)",
        "severity": "CRITICAL", "cvss": "9.8",
        "cwe": "CWE-798", "owasp": "A07:2021",
        "evidence": ("High-entropy AWS/GCP/Azure access keys committed to the "
                     "repository. Verified via Shannon entropy > 4.0 "
                     "(verification_method=shannon_entropy_check). "
                     f"Sample files: {sample}"),
        "remediation": ("CRITICAL - rotate the leaked cloud credentials IMMEDIATELY "
                        "in the cloud console (IAM -> deactivate -> create new -> "
                        "delete old). Audit CloudTrail / Cloud Audit Logs for "
                        "unauthorized use since the commit date. Then purge the "
                        "secrets from git history (`git filter-repo --replace-text`) "
                        "AND force-push. Adding the file to .gitignore is NOT "
                        "enough - the secret is still in the commit history."),
    }


def rule_confirmed_private_key(s):
    g = _findings_by_severity_and_type(s)
    if not g["key_material"]:
        return None
    sample = ", ".join(f.get("file", "?") for f in g["key_material"][:3])
    return {
        "name": f"CONFIRMED leaked private key material ({len(g['key_material'])} key)",
        "severity": "CRITICAL", "cvss": "9.4",
        "cwe": "CWE-798", "owasp": "A07:2021",
        "evidence": ("BEGIN PRIVATE KEY block(s) detected in commits "
                     "(RSA / EC / OPENSSH / PGP). Anyone with read access to "
                     "the repo or its history holds the key. "
                     f"Sample files: {sample}"),
        "remediation": ("CRITICAL - revoke the compromised key on every system "
                        "that trusts it (SSH authorized_keys, GPG keyring, TLS "
                        "cert authority). Generate replacement keypair. Purge "
                        "key material from git history with `git filter-repo`. "
                        "If a TLS private key leaked, revoke + re-issue the "
                        "certificate."),
    }


def rule_confirmed_api_token(s):
    g = _findings_by_severity_and_type(s)
    if not g["service_token"]:
        return None
    sample = ", ".join(f.get("file", "?") for f in g["service_token"][:3])
    return {
        "name": f"CONFIRMED leaked API service token ({len(g['service_token'])} token)",
        "severity": "HIGH", "cvss": "8.1",
        "cwe": "CWE-798", "owasp": "A07:2021",
        "evidence": ("High-entropy GitHub / Slack / Stripe / similar service "
                     "token committed to the repo. Verified via Shannon entropy "
                     f"check. Sample files: {sample}"),
        "remediation": ("Revoke the token in the issuing provider's dashboard "
                        "(GitHub -> Settings -> Developer settings -> revoke; "
                        "Slack -> App management -> regenerate; etc). Generate "
                        "a replacement and store in a secrets manager (Vault, "
                        "AWS Secrets Manager, Doppler). Purge from git history."),
    }


def rule_confirmed_credential(s):
    g = _findings_by_severity_and_type(s)
    if not g["credential"]:
        return None
    sample = ", ".join(f.get("file", "?") for f in g["credential"][:3])
    return {
        "name": f"CONFIRMED leaked generic credential ({len(g['credential'])} secret)",
        "severity": "MEDIUM", "cvss": "6.5",
        "cwe": "CWE-798", "owasp": "A07:2021",
        "evidence": ("password=/secret=/api_key= style assignment with a "
                     "high-entropy value committed to the repo. "
                     f"Sample files: {sample}"),
        "remediation": ("Rotate the affected credential (database password, "
                        "internal API key, etc). Move to environment variables "
                        "or a secrets manager. Add the source file pattern to "
                        ".gitignore and purge the value from history."),
    }


def rule_suspected_secret(s):
    g = _findings_by_severity_and_type(s)
    if not g["suspected"]:
        return None
    sample = ", ".join(f.get("file", "?") for f in g["suspected"][:5])
    return {
        "name": f"SUSPECTED secret-like string ({len(g['suspected'])} - needs manual review)",
        "severity": "LOW", "cvss": "3.7",
        "cwe": "CWE-798", "owasp": "A07:2021",
        "evidence": ("Pattern matched a secret rule but value is low-entropy or "
                     "matches a common placeholder (password123, changeme, "
                     "example_token, etc). Could be a real weak secret or a "
                     f"docs placeholder. Sample files: {sample}"),
        "remediation": ("Manually inspect each match. If real -> rotate + purge "
                        "from history. If placeholder -> replace with an obvious "
                        "<REDACTED> marker so future scans skip it."),
    }


def rule_chain_handoff(s):
    chain_next = s.get("chain_next") or []
    if not chain_next:
        return None
    return {
        "name": "Cross-scanner chain handoff suggested",
        "severity": "INFO",
        "evidence": ("Confirmed leaked credentials enable downstream auditing: " +
                     ", ".join(chain_next)),
        "remediation": ("Re-run with chain_id propagation to automatically follow "
                        "up with: " + ", ".join(chain_next) + ". These will "
                        "inherit the captured credentials via the VL-METHOD "
                        "chaining engine and audit blast radius."),
        "cwe": "CWE-1006",
    }


GIT_SECRETS_SCAN_FINDING_RULES = [
    rule_input_missing,
    rule_gitleaks_missing,
    rule_positive_clean,
    rule_confirmed_cloud_creds,
    rule_confirmed_private_key,
    rule_confirmed_api_token,
    rule_confirmed_credential,
    rule_suspected_secret,
    rule_chain_handoff,
]
