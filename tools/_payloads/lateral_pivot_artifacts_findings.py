"""lateral_pivot_artifacts - findings rules.

Severity model:
  HIGH      private SSH key / aws creds / .docker config with auth / kube
            config / git-credentials / authorized_keys with > 1 entries
  MEDIUM    browser cookie DBs / ssh-agent forward sockets
  INFO      SSH creds missing / paramiko missing / connection failed
  POSITIVE  hunt ran, target had none of the above
"""


def rule_high_creds(s):
    hits = s.get("lateral_pivot_high_artifacts") or []
    if not hits:
        return None
    categories = sorted({h.get("category") for h in hits if h.get("category")})
    sample = "; ".join(
        f"{h.get('category')}: {h.get('path', '?')}"
        for h in hits[:5]
    )
    fresh_count = sum(1 for h in hits if h.get("fresh"))
    return {
        "name": (f"Lateral-pivot credentials discoverable on host "
                 f"({len(hits)} credential files across "
                 f"{', '.join(categories)})"),
        "severity": "HIGH",
        "cvss": "8.5",
        "cwe": "CWE-552",
        "owasp": "A04:2021",
        "mitre": "T1552.001, T1552.004, T1098.004",
        "evidence": (
            f"Discoverable artifacts: {sample}. "
            f"{fresh_count} of {len(hits)} modified in last 7 days."
        ),
        "remediation": (
            "1. For each private-key / token file, validate with the user "
            "whether the credential is still needed; if not, delete. 2. Move "
            "long-lived AWS keys to IAM roles + instance profile (.aws/"
            "credentials should not exist on production hosts). 3. Use "
            "`docker logout` to clear .docker/config.json auth blocks; use "
            "OIDC-federated registry auth instead. 4. Audit ~/.ssh/"
            "authorized_keys: only the keys actively rotated through your "
            "key-management tool should be present. 5. Once cleaned, set up "
            "auditd file-watches on .aws/, .docker/, .kube/, and .ssh/ to "
            "alert on re-creation."
        ),
    }


def rule_medium(s):
    hits = s.get("lateral_pivot_medium_artifacts") or []
    if not hits:
        return None
    categories = sorted({h.get("category") for h in hits if h.get("category")})
    fresh_count = sum(1 for h in hits if h.get("fresh"))
    return {
        "name": (f"Lateral-pivot data-collection artifacts present "
                 f"({len(hits)} in {', '.join(categories)})"),
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-200",
        "owasp": "A04:2021",
        "mitre": "T1539, T1552.004",
        "evidence": (
            f"{len(hits)} artifacts (ssh-agent sockets, browser cookie DBs). "
            f"{fresh_count} modified in last 7 days."
        ),
        "remediation": (
            "1. Disable SSH agent forwarding to this host (`ForwardAgent no` "
            "in client config + `AllowAgentForwarding no` server-side) - "
            "forwarded agent sockets let any root-on-host user impersonate "
            "the connected user. 2. For developer workstations, accept that "
            "browser cookie DBs exist; for servers, ensure no browser is "
            "installed (`apt remove chromium firefox-esr`)."
        ),
    }


def rule_fresh(s):
    fresh = s.get("lateral_pivot_fresh_artifacts") or []
    if not fresh:
        return None
    if len(fresh) < 3:
        return None
    return {
        "name": (f"Multiple credential artifacts modified in last 7 days "
                 f"({len(fresh)} files)"),
        "severity": "MEDIUM",
        "cvss": "4.3",
        "cwe": "CWE-552",
        "owasp": "A04:2021",
        "mitre": "T1552.001",
        "evidence": (
            f"{len(fresh)} discoverable-credential files have mtime within "
            "the last 7 days. This is consistent with either active "
            "developer use OR attacker collection prep - investigate to "
            "distinguish."
        ),
        "remediation": (
            "Correlate file mtimes with sudo and SSH login times from "
            "/var/log/auth.log. If the mtime matches a session you "
            "recognize, no action; otherwise treat as IOC and rotate the "
            "associated credentials."
        ),
    }


def rule_creds_missing(s):
    if not s.get("lateral_pivot_creds_missing"):
        return None
    return {
        "name": "Lateral-pivot artifact hunt skipped - SSH credentials not supplied",
        "severity": "INFO",
        "evidence": ("Requires options.username + options.password (or "
                     "options.ssh_key) to enumerate per-user home dirs."),
        "remediation": ("Re-run with credentials. Recommended: use a "
                        "key-based audit account with read access to /home "
                        "(via group membership) so no password is on the "
                        "wire."),
        "cwe": "CWE-1006",
    }


def rule_auth_failed(s):
    if not s.get("lateral_pivot_ssh_auth_failed"):
        return None
    return {
        "name": "SSH authentication failed during lateral-pivot hunt",
        "severity": "INFO",
        "evidence": "paramiko returned AuthenticationException.",
        "remediation": "Verify the credential is valid; check /var/log/auth.log.",
        "cwe": "CWE-287",
    }


def rule_paramiko_missing(s):
    if "paramiko not installed" not in str(s.get("lateral_pivot_artifacts_error") or ""):
        return None
    return {
        "name": "paramiko library not installed on scanner host",
        "severity": "INFO",
        "evidence": "import paramiko failed.",
        "remediation": "pip install paramiko.",
        "cwe": "CWE-1006",
    }


def rule_connect_error(s):
    err = str(s.get("lateral_pivot_artifacts_error") or "")
    if not err or "paramiko" in err:
        return None
    if "ssh" not in err.lower():
        return None
    return {
        "name": "SSH connection failed during lateral-pivot hunt",
        "severity": "INFO",
        "evidence": f"paramiko: {err}",
        "remediation": ("Verify SSH reachability + firewall rules; re-run "
                        "after fixing connectivity."),
        "cwe": "CWE-1006",
    }


def rule_positive(s):
    if s.get("lateral_pivot_artifacts_total"):
        return None
    if s.get("lateral_pivot_creds_missing"):
        return None
    if s.get("lateral_pivot_ssh_auth_failed"):
        return None
    if s.get("lateral_pivot_artifacts_error"):
        return None
    return {
        "name": "No lateral-pivot credential artifacts on host",
        "severity": "POSITIVE",
        "evidence": (
            "Audit found no .aws/credentials, .kube/config, .docker/"
            "config.json, .git-credentials, SSH private keys, "
            "extra authorized_keys entries, agent-forward sockets, or "
            "browser cookie DBs in audited user homes."
        ),
        "remediation": (
            "Maintain clean state: enforce IAM-role-based auth for cloud, "
            "OIDC-federated for registries, ephemeral SSH keys via "
            "Vault/SSH-CA. Re-run this audit monthly to catch regressions."
        ),
        "cwe": "CWE-552",
    }


LATERAL_PIVOT_ARTIFACTS_FINDING_RULES = [
    rule_high_creds,
    rule_medium,
    rule_fresh,
    rule_creds_missing,
    rule_auth_failed,
    rule_paramiko_missing,
    rule_connect_error,
    rule_positive,
]
