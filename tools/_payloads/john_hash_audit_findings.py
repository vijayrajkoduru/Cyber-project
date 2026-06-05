"""john_hash_audit - finding rules (VL-METHOD aware).

REWRITTEN 2026-06-05 for the VL-METHOD methodology pattern. Reads new
state keys populated by JohnHashAudit's 7-stage flow:
  - methodology_findings   : list of verified cracked-hash findings
  - hash_count             : int from pre_flight
  - fingerprint            : dict {hash_types, salt_present, ambiguous_count, unique_formats}
  - quick_probe_attempts   : int
  - quick_probe_cracked    : int
  - deep_scan_cracked      : int
  - chain_next             : list of follow-up scanner names
  - skipped_reason         : str (when pre_flight returned False)
  - john_missing           : bool (binary not installed)

Severity matrix (per CONFIRMED finding):
  CONFIRMED root NTLM/admin / shadow uid=0  -> CRITICAL  CVSS 9.8
  CONFIRMED Windows NTLM (non-admin)        -> HIGH      CVSS 8.1
  CONFIRMED Linux user shadow               -> HIGH      CVSS 7.5
  CONFIRMED WPA PSK                          -> HIGH      CVSS 7.5
  CONFIRMED webapp bcrypt/argon2/htpasswd   -> MEDIUM    CVSS 6.5
  CONFIRMED raw unsalted (md5/sha1)         -> MEDIUM    CVSS 6.0
  SUSPECTED any                              -> LOW       CVSS 3.7
"""


# ───────────── pre-stage / sanity rules ─────────────

def rule_no_hashes_supplied(s):
    reason = s.get("skipped_reason") or ""
    if "options.hashes" not in reason:
        return None
    return {
        "name": "John hash audit skipped - no hashes supplied",
        "severity": "INFO",
        "evidence": reason,
        "remediation": (
            "Re-run with options.hashes set to a newline-separated list of "
            "password hashes. Accepts raw hashes (one per line) or full "
            "/etc/shadow lines. Max 100 hashes per scan. Example formats: "
            "'$6$abc...$xyz...' (sha512crypt), '$2y$12$...' (bcrypt), "
            "32-hex (NTLM/MD5), 'user:rid:LM:NTLM:::' (pwdump)."
        ),
        "cwe": "CWE-1006",
    }


def rule_binary_missing(s):
    if not s.get("john_missing"):
        return None
    return {
        "name": "John the Ripper binary not installed on scanner host",
        "severity": "INFO",
        "evidence": "shutil.which('john') returned None during pre_flight.",
        "remediation": (
            "Install john: apt install john (Debian/Kali). For best coverage "
            "use john-jumbo (community-jumbo edition) which supports 200+ "
            "hash formats. VulnusLab backend image should already include "
            "john - check Dockerfile if this fires in production."
        ),
        "cwe": "CWE-1006",
    }


def rule_unsupported_format(s):
    fp = s.get("fingerprint") or {}
    ambiguous = fp.get("ambiguous_count", 0)
    unique = fp.get("unique_formats") or []
    if not ambiguous or "unknown" not in unique:
        return None
    return {
        "name": f"John hash audit - {ambiguous} hash(es) had unrecognized format",
        "severity": "INFO",
        "evidence": (
            f"Algorithm detection could not classify {ambiguous} of the supplied "
            f"hashes. Detected formats overall: {', '.join(unique)}. Unknown-format "
            "hashes are skipped during crack passes (john cannot pick --format=auto "
            "for arbitrary input)."
        ),
        "remediation": (
            "Identify the hash format manually (use online hashID or "
            "`hashid <hash>` on a Kali shell), then either re-submit with the "
            "hash in its canonical form (e.g. prepend '$1$' for md5crypt, "
            "wrap WPA hashes in '$WPAPSK$...$' format) or split the batch by "
            "known format. Unknown 32-hex strings could be MD5 / NTLM / LM - "
            "context (where you extracted them) usually disambiguates."
        ),
        "cwe": "CWE-1006",
    }


def rule_no_wordlist(s):
    if not (s.get("quick_no_wordlist") or s.get("deep_no_wordlist")):
        return None
    which = []
    if s.get("quick_no_wordlist"): which.append("quick_probe (top-100)")
    if s.get("deep_no_wordlist"):  which.append("deep_scan (rockyou)")
    return {
        "name": f"John hash audit - wordlist missing for: {', '.join(which)}",
        "severity": "INFO",
        "evidence": (
            "None of the expected wordlists were found on disk: "
            "/opt/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt, "
            "/usr/share/wordlists/rockyou.txt, /opt/seclists/.../rockyou.txt."
        ),
        "remediation": (
            "Install wordlists on the scanner host: apt install seclists wordlists && "
            "gunzip /usr/share/wordlists/rockyou.txt.gz. Or build the backend image "
            "with /opt/seclists baked in (VulnusLab Dockerfile should already do this)."
        ),
        "cwe": "CWE-1006",
    }


# ───────────── grouping for severity rules ─────────────

def _findings_by_severity(s):
    """Bucket methodology_findings into severity tiers based on confidence
    + credential_context + privilege_level."""
    out = {
        "CRITICAL": [],   # root windows/linux
        "HIGH_NTLM": [],  # windows non-admin
        "HIGH_SHADOW": [],# linux user
        "HIGH_WPA": [],   # wifi psk
        "MEDIUM_WEB": [], # webapp bcrypt/argon2/htpasswd
        "MEDIUM_RAW": [], # raw unsalted
        "LOW": [],        # SUSPECTED / unknown
    }
    for f in (s.get("methodology_findings") or []):
        conf = f.get("confidence", "SUSPECTED")
        if conf != "CONFIRMED":
            out["LOW"].append(f)
            continue
        cred_ctx = f.get("credential_context", "")
        priv = f.get("privilege_level", "unknown")
        if priv == "root" and cred_ctx in ("windows_credential",
                                            "windows_credential_lm_weak",
                                            "linux_shadow",
                                            "ad_account"):
            out["CRITICAL"].append(f)
        elif cred_ctx in ("windows_credential", "windows_credential_lm_weak"):
            out["HIGH_NTLM"].append(f)
        elif cred_ctx == "linux_shadow":
            out["HIGH_SHADOW"].append(f)
        elif cred_ctx == "wifi_psk":
            out["HIGH_WPA"].append(f)
        elif cred_ctx in ("webapp_user", "webapp_htpasswd"):
            out["MEDIUM_WEB"].append(f)
        elif cred_ctx == "raw_unsalted":
            out["MEDIUM_RAW"].append(f)
        else:
            out["LOW"].append(f)
    return out


def _names_csv(findings, n=5):
    parts = []
    for f in findings[:n]:
        u = f.get("username") or f.get("hash_marker") or "?"
        ht = f.get("hash_type", "?")
        parts.append(f"{u} ({ht})")
    return ", ".join(parts)


# ───────────── severity rules (cracked findings) ─────────────

def rule_confirmed_critical(s):
    g = _findings_by_severity(s)
    if not g["CRITICAL"]:
        return None
    return {
        "name": f"CONFIRMED root/admin password cracked offline ({len(g['CRITICAL'])} account)",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-521",
        "owasp": "A07:2021",
        "evidence": (
            "Privileged account password(s) recovered from hash batch. "
            "Verified by passlib re-hash match (verification_method="
            "passlib_rehash_match). Compromised principals: "
            + _names_csv(g["CRITICAL"]) +
            " — cleartext suppressed per VulnusLab policy; only length+last-2 "
            "marker visible in detail view."
        ),
        "remediation": (
            "CRITICAL - rotate the affected privileged credentials IMMEDIATELY "
            "on the source host(s)/domain. For Windows: reset Administrator/"
            "krbtgt (twice for krbtgt to invalidate any golden tickets); enable "
            "Credential Guard + LAPS for local-admin rotation. For Linux /etc/"
            "shadow: passwd -e root + force change at next login + audit "
            "/var/log/auth.log for prior abuse. Migrate weak hash schemes to "
            "argon2id / sha512crypt rounds>=500000 / bcrypt cost>=12. Treat "
            "any host where these hashes lived as potentially compromised."
        ),
    }


def rule_confirmed_ntlm(s):
    g = _findings_by_severity(s)
    if not g["HIGH_NTLM"]:
        return None
    return {
        "name": f"CONFIRMED Windows NTLM credential cracked ({len(g['HIGH_NTLM'])} account)",
        "severity": "HIGH",
        "cvss": "8.1",
        "cwe": "CWE-916",
        "owasp": "A02:2021",
        "evidence": (
            "Windows NTLM hash(es) cracked. Even without admin, the cleartext "
            "enables pass-the-hash + cred-reuse lateral movement across "
            "domain-joined hosts. Verified by passlib nthash match. Accounts: "
            + _names_csv(g["HIGH_NTLM"]) + "."
        ),
        "remediation": (
            "1. Force password reset on the affected accounts at next logon. "
            "2. Enable Credential Guard + Defender-for-Identity to detect PtH "
            "attempts. 3. Migrate to passwordless auth (Windows Hello for "
            "Business / FIDO2 keys) for these users. 4. Set domain password "
            "policy to 14+ chars + banned-words list (Azure AD Password "
            "Protection). 5. Re-run audit after rotation - confirmed count "
            "should drop to 0."
        ),
    }


def rule_confirmed_shadow(s):
    g = _findings_by_severity(s)
    if not g["HIGH_SHADOW"]:
        return None
    return {
        "name": f"CONFIRMED Linux /etc/shadow password cracked ({len(g['HIGH_SHADOW'])} account)",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-916",
        "owasp": "A07:2021",
        "evidence": (
            "Linux user shadow hash(es) recovered. Cleartext enables direct "
            "SSH/console login as the user, plus likely credential reuse on "
            "other systems (60% of users reuse passwords across services). "
            "Verified by passlib sha512_crypt / sha256_crypt / md5_crypt "
            "match. Accounts: " + _names_csv(g["HIGH_SHADOW"]) + "."
        ),
        "remediation": (
            "1. Force password reset for the affected users (passwd -e <user>). "
            "2. Notify the account owners + tell them to rotate this password "
            "everywhere they reused it. 3. Migrate /etc/shadow to yescrypt or "
            "sha512crypt with rounds>=500000 (configurable in /etc/login.defs "
            "ENCRYPT_METHOD + SHA_CRYPT_MIN_ROUNDS). 4. Disable password auth "
            "on SSH for these users (force key-only): set PasswordAuthentication "
            "no per-Match block in sshd_config."
        ),
    }


def rule_confirmed_wpa(s):
    g = _findings_by_severity(s)
    if not g["HIGH_WPA"]:
        return None
    return {
        "name": f"CONFIRMED WPA pre-shared key cracked ({len(g['HIGH_WPA'])} network)",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-326",
        "owasp": "A02:2021",
        "evidence": (
            "WPA/WPA2-PSK pre-shared key recovered from captured 4-way "
            "handshake. Attacker within RF range can now decrypt all traffic + "
            "join the wireless network. Networks: " +
            ", ".join(f.get("username") or f.get("hash_marker", "?") for f in g["HIGH_WPA"][:5]) + "."
        ),
        "remediation": (
            "1. Rotate the WPA PSK immediately on the affected SSID(s). "
            "2. Pick a 20+ char random passphrase (high-entropy, not dictionary). "
            "3. Migrate to WPA3-SAE if APs support it (SAE is resistant to "
            "offline dictionary attack). 4. For enterprise: switch to WPA2/3-"
            "Enterprise with EAP-TLS (certificate auth, no shared secret). "
            "5. Audit DHCP leases for unknown clients during the exposure window."
        ),
    }


def rule_confirmed_webapp(s):
    g = _findings_by_severity(s)
    if not g["MEDIUM_WEB"]:
        return None
    return {
        "name": f"CONFIRMED webapp password cracked ({len(g['MEDIUM_WEB'])} account)",
        "severity": "MEDIUM",
        "cvss": "6.5",
        "cwe": "CWE-521",
        "owasp": "A07:2021",
        "evidence": (
            "Webapp credential (bcrypt / argon2 / htpasswd) cracked. Despite "
            "using a memory-hard scheme, the underlying password was weak "
            "enough to fall to wordlist+rules attack. Accounts: " +
            _names_csv(g["MEDIUM_WEB"]) + "."
        ),
        "remediation": (
            "1. Force password reset on the affected webapp accounts. "
            "2. Notify users + audit application access logs for the exposure "
            "window. 3. Enforce 14+ char minimum + reject top-10k breached "
            "passwords (HIBP Pwned Passwords API on signup/change). "
            "4. Roll out MFA (TOTP / WebAuthn) so a cracked password alone "
            "doesn't grant access. 5. Bump bcrypt cost to 12+ or migrate to "
            "argon2id (memory=64MB, iterations=3, parallelism=4)."
        ),
    }


def rule_confirmed_raw_unsalted(s):
    g = _findings_by_severity(s)
    if not g["MEDIUM_RAW"]:
        return None
    return {
        "name": f"CONFIRMED unsalted hash cracked ({len(g['MEDIUM_RAW'])} - weak scheme)",
        "severity": "MEDIUM",
        "cvss": "6.0",
        "cwe": "CWE-916",
        "owasp": "A02:2021",
        "evidence": (
            "Raw unsalted hash(es) (md5/sha1/sha256/sha512) cracked. The "
            "lack of salt + use of a fast hash makes these trivially "
            "rainbow-table-able even before john runs. Compromised: " +
            _names_csv(g["MEDIUM_RAW"]) + "."
        ),
        "remediation": (
            "Migrate from raw hex digests to a salted memory-hard scheme: "
            "argon2id (preferred, OWASP 2024 recommendation) or bcrypt "
            "cost>=12. Re-hash all stored passwords on next user login + "
            "expire passwords older than the migration cutoff. Audit any "
            "API/DB dump exposure that could have leaked these hashes."
        ),
    }


def rule_suspected(s):
    g = _findings_by_severity(s)
    if not g["LOW"]:
        return None
    suspected = [f for f in g["LOW"] if f.get("confidence") == "SUSPECTED"]
    if not suspected:
        return None
    return {
        "name": f"SUSPECTED hash crack ({len(suspected)} - needs manual confirmation)",
        "severity": "LOW",
        "cvss": "3.7",
        "cwe": "CWE-521",
        "evidence": (
            "John reported these hashes as cracked, but passlib re-hash "
            "verification could not confirm the plaintext matches the "
            "original hash. Usually means passlib lacks support for the "
            "algorithm (e.g. yescrypt, krb5pa-md5) OR a salt-parsing edge "
            "case. Affected: " + _names_csv(suspected) + "."
        ),
        "remediation": (
            "Manually verify by attempting login with the redacted-marker "
            "guidance, or re-run with --format=auto in a john-jumbo shell to "
            "double-check. If passlib doesn't support the algorithm, install "
            "the relevant module (pip install passlib[argon2] / passlib[bcrypt] "
            "/ krb5-python) on the scanner host to enable rehash verify."
        ),
    }


# ───────────── positive + chain rules ─────────────

def rule_positive(s):
    """All hashes survived both quick + deep passes - good password strength."""
    if (s.get("methodology_findings") or []):
        return None
    if s.get("skipped_reason"):
        return None
    if s.get("john_missing"):
        return None
    in_count = s.get("hash_count") or 0
    if not in_count:
        return None
    quick = s.get("quick_probe_attempts") or 0
    fp = s.get("fingerprint") or {}
    fmts = ", ".join(fp.get("unique_formats") or ["?"])
    return {
        "name": "Hash batch survived John the Ripper wordlist+rules audit",
        "severity": "POSITIVE",
        "evidence": (
            f"{in_count} hash(es) audited against quick-probe (top-100) "
            f"+ deep-scan (rockyou with rules). Zero cracks within wall-"
            f"clock cap. Detected formats: {fmts}. Quick-probe attempts: "
            f"{quick}."
        ),
        "remediation": (
            "Strong sign your password policy is resisting common attacks. "
            "Re-audit on every quarterly password rotation AND after every "
            "major breach corpus release (e.g. RockYou2024, COMB). For even "
            "more confidence, schedule a hashcat GPU pass with rule "
            "stacking (best64 + dive + OneRuleToRuleThemAll)."
        ),
        "cwe": "CWE-521",
        "owasp": "A07:2021",
    }


def rule_chain_handoff(s):
    chain_next = s.get("chain_next") or []
    if not chain_next:
        return None
    return {
        "name": "Cross-scanner chain handoff suggested",
        "severity": "INFO",
        "evidence": (
            "Cracked credentials enable downstream scanners to exercise "
            "cred-reuse / lateral-movement attack paths: " +
            ", ".join(chain_next) + "."
        ),
        "remediation": (
            "Re-run those scanners with chain_id propagation so they "
            "automatically inherit the captured credentials via the "
            "VL-METHOD chaining engine. Suggested order: " +
            " -> ".join(chain_next) + "."
        ),
        "cwe": "CWE-1006",
    }


JOHN_HASH_AUDIT_FINDING_RULES = [
    rule_no_hashes_supplied,
    rule_binary_missing,
    rule_unsupported_format,
    rule_no_wordlist,
    rule_confirmed_critical,
    rule_confirmed_ntlm,
    rule_confirmed_shadow,
    rule_confirmed_wpa,
    rule_confirmed_webapp,
    rule_confirmed_raw_unsalted,
    rule_suspected,
    rule_positive,
    rule_chain_handoff,
]
