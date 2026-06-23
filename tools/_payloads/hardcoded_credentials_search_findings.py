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
    # Narrowed to live-token material that grants access BY ITSELF (slack/PGP-
    # priv/JWT/basic-auth). Password / shadow / bcrypt HASHES are handled
    # separately as INFO inventory (they must be cracked, KDF-gated).
    cats = s.get("secrets_by_category") or {}
    high_cats = s.get("secrets_high_categories") or [
        c for c in ("slack_token", "pgp_priv", "jwt_token", "basic_auth_b64")
        if cats.get(c)]
    if not high_cats:
        return None
    detail = ", ".join(f"{c}={cats.get(c, 0)}" for c in high_cats)
    return {"name": f"High-severity secret material in firmware: {', '.join(high_cats)}",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-798", "owasp": "A07:2021",
            "evidence": f"Patterns matched: {detail}",
            "remediation": ("JWT tokens may grant API access until expiry. Slack/basic-auth "
                            "blobs are live bearer credentials. PGP private keys allow "
                            "decryption of any data encrypted to that key. "
                            "Rotate immediately and remove from firmware build.")}


def rule_aws_key_id_inventory(s):
    # An AWS access-key ID (AKIA/ASIA + 16 chars) is a PUBLIC identifier, not a
    # secret. CRITICAL only when paired with a secret (handled by
    # rule_critical_secrets). Otherwise it is an INFO inventory item.
    if not s.get("secrets_aws_key_id_only"):
        return None
    cats = s.get("secrets_by_category") or {}
    n = cats.get("aws_access_key", 0)
    return {"name": f"AWS access-key ID(s) found in firmware ({n}) — public identifier, no paired secret",
            "severity": "INFO",
            "cwe": "CWE-798", "owasp": "A07:2021",
            "evidence": (f"aws_access_key={n}; the matching 40-char AWS SECRET value was NOT "
                         f"found nearby, so this access-key ID is a public identifier, not an "
                         f"exploitable secret by itself."),
            "remediation": ("An AWS access-key ID alone cannot authenticate without its secret. "
                            "Confirm whether the key is still active in AWS IAM (Last used) and "
                            "disable it if unrecognised. Locate the paired secret if it is "
                            "provisioned at runtime; never ship either in firmware.")}


def rule_password_hash_inventory(s):
    # Password / shadow / bcrypt HASHES are not exploitable by themselves —
    # they must be cracked offline and that is gated by KDF strength. Report as
    # INFO inventory, NOT HIGH.
    cats = s.get("secrets_by_category") or {}
    hash_cats = s.get("secrets_hash_categories") or [
        c for c in ("bcrypt_hash", "shadow_hash_md5", "shadow_hash_sha",
                    "shadow_hash_yes") if cats.get(c)]
    if not hash_cats:
        return None
    detail = ", ".join(f"{c}={cats.get(c, 0)}" for c in hash_cats)
    weak = [c for c in hash_cats if c in ("shadow_hash_md5",)]
    return {"name": f"Password / shadow hashes present in firmware: {', '.join(hash_cats)}",
            "severity": "INFO",
            "cwe": "CWE-798", "owasp": "A07:2021",
            "evidence": f"Hash material matched: {detail}",
            "remediation": ("These are password HASHES, not cleartext credentials — they are not "
                            "exploitable by themselves and must be cracked offline (john/hashcat), "
                            "which is gated by the KDF strength. Confirm a strong KDF is used "
                            "(bcrypt/yescrypt/sha512crypt with high rounds — NOT md5crypt)"
                            + (" — md5crypt ($1$) hashes were found and crack quickly." if weak else ".")
                            + " Ship an empty /etc/shadow and force a first-boot password set so no "
                            "hash leaves the factory.")}


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
                                                rule_high_secrets,
                                                rule_aws_key_id_inventory,
                                                rule_password_hash_inventory,
                                                rule_system_account_creds]
