"""hardcoded_credentials_search - findings rules."""


def rule_positive(s):
    if s.get("hardcoded_credentials_search_total"):
        return None
    if s.get("hardcoded_credentials_search_error"):
        return None
    return {"name": "No hardcoded credentials matched by byte-level patterns",
            "severity": "POSITIVE",
            "evidence": "AWS/Google/GitHub/Stripe/Slack/OpenSSH/JWT regex passes returned no hits",
            "remediation": ("Continue keeping secrets out of firmware. Bind credentials at "
                            "provisioning (TPM-sealed / fuse-burned) and rotate periodically."),
            "cwe": "CWE-798", "owasp": "A07:2021"}


def rule_critical_secrets(s):
    cats = s.get("secrets_critical_categories") or []
    counts = s.get("secrets_by_category") or {}
    if not cats:
        return None
    detail = ", ".join(f"{c}={counts.get(c, 0)}" for c in cats)
    return {"name": f"Critical hardcoded secrets in firmware: {', '.join(cats)}",
            "severity": "CRITICAL", "cvss": "9.8",
            "cwe": "CWE-798", "owasp": "A07:2021",
            "evidence": f"Byte-level regex matched: {detail}",
            "remediation": ("These are validated cred patterns — treat as compromised. "
                            "(1) Rotate every matching credential immediately at the issuer "
                            "(AWS IAM / GCP / GitHub Settings / Stripe Dashboard). "
                            "(2) Audit usage logs for the past 90 days. "
                            "(3) Remove from source + scrub git history. "
                            "(4) Add gitleaks / trufflehog to CI gate. "
                            "(5) Replace with runtime-fetched tokens (mTLS to provisioning server) "
                            "or TPM-sealed secrets in production firmware.")}


def rule_high_secrets(s):
    cats = s.get("secrets_by_category") or {}
    high_cats = [c for c in ("slack_token", "pgp_priv", "bcrypt_hash", "shadow_hash_md5",
                             "shadow_hash_sha", "shadow_hash_yes", "jwt_token",
                             "basic_auth_b64") if cats.get(c)]
    if not high_cats:
        return None
    detail = ", ".join(f"{c}={cats[c]}" for c in high_cats)
    return {"name": f"High-severity secret material in firmware: {', '.join(high_cats)}",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-798", "owasp": "A07:2021",
            "evidence": f"Patterns matched: {detail}",
            "remediation": ("Shadow hashes can be cracked offline (john/hashcat) — assume root "
                            "password breach. JWT tokens may grant API access until expiry. "
                            "PGP private keys allow decryption of any data encrypted to that key. "
                            "Rotate immediately and remove from firmware build. "
                            "For shadow: ship empty /etc/shadow + force first-boot password set.")}


def rule_system_account_creds(s):
    cats = s.get("secrets_by_category") or {}
    med_cats = [c for c in ("telnet_passwd", "hardcoded_root") if cats.get(c)]
    if not med_cats:
        return None
    return {"name": "System account credentials embedded in firmware",
            "severity": "MEDIUM", "cvss": "6.5",
            "cwe": "CWE-798", "owasp": "A07:2021",
            "evidence": f"Patterns: {', '.join(med_cats)} "
                        f"({', '.join(f'{c}={cats[c]}' for c in med_cats)})",
            "remediation": ("Hardcoded root passwords / telnet credentials enable trivial fleet-wide "
                            "device takeover (Mirai-style botnets). Disable telnet entirely (use "
                            "SSH on host-keyed first-boot). Force unique device-bound password on "
                            "first power-up via web UI or QR-code provisioning. Comply with "
                            "ETSI EN 303 645 §5.1-1 (no universal default passwords).")}


HARDCODED_CREDENTIALS_SEARCH_FINDING_RULES = [rule_positive, rule_critical_secrets,
                                                rule_high_secrets, rule_system_account_creds]
