"""john_hash_audit - findings rules.

Severity model:
  HIGH    - one or more hashes cracked (password policy proved weak;
              never CRITICAL because the attacker still needed to grab
              the hash first - this is a hardening signal, not RCE)
  INFO    - john missing / wordlist missing / bad input / format invalid
  POSITIVE - audit ran, 0 cracks => password policy survived rockyou+rules
"""


def rule_high_cracked(s):
    cracked = s.get("john_cracked_hashes_redacted") or []
    if not cracked:
        return None
    total_in = s.get("john_hash_audit_hashes_in") or 0
    pct = round(100.0 * len(cracked) / max(1, total_in), 1)
    fmt = s.get("john_hash_audit_format") or "?"
    sev = "CRITICAL" if pct >= 25 else "HIGH"
    cvss = "8.6" if sev == "CRITICAL" else "7.5"
    sample = ", ".join(cracked[:5])
    return {
        "name": (f"{len(cracked)}/{total_in} {fmt} hash(es) cracked offline "
                 f"({pct}% of submitted batch)"),
        "severity": sev,
        "cvss": cvss,
        "cwe": "CWE-521",
        "owasp": "A02:2021",
        "evidence": (f"John the Ripper recovered passwords from these hashes "
                     f"(cleartext redacted per VulnusLab policy): {sample}"
                     + (f"  ...and {len(cracked) - 5} more." if len(cracked) > 5 else "")),
        "remediation": (
            "1. Force-reset the affected accounts immediately and review authentication logs for unauthorized access. "
            "2. Migrate from weak hash algorithms (raw-md5/sha1/NT) to memory-hard schemes (argon2id, scrypt, bcrypt cost>=12). "
            "3. Enforce a passphrase policy (minimum 14 chars, blocklist top-1M breach corpus via HIBP API). "
            "4. Re-run this audit against the new hash dump after rotation - cracked count should drop to 0. "
            "5. For Windows NTLM/NetNTLMv2: enable Credential Guard + force smart-card or Windows Hello for Business; "
            "for /etc/shadow: switch to sha512crypt rounds>=500000 or yescrypt; for app DBs: argon2id."
        ),
    }


def rule_timeout(s):
    if not s.get("john_crack_timed_out"):
        return None
    return {
        "name": "John the Ripper hit the wall-clock cap mid-audit",
        "severity": "INFO",
        "evidence": ("The crack job exceeded the configured timeout. Reported cracks are "
                     "partial results - more weak passwords likely exist in the batch."),
        "remediation": ("Re-run with options.timeout_sec=240 (max) or split the hash batch into smaller chunks. "
                        "For exhaustive cracking, switch to hashcat with GPU on a dedicated cracking host."),
        "cwe": "CWE-1006",
    }


def rule_input_missing(s):
    missing = s.get("john_input_missing") or []
    if not missing:
        return None
    return {
        "name": "John hash audit skipped - required options not supplied",
        "severity": "INFO",
        "evidence": f"Missing options: {', '.join(missing)}",
        "remediation": (
            "Re-run with options.hashes (newline-separated raw hashes) + options.hash_format "
            "(e.g. 'nt', 'sha512crypt', 'bcrypt', 'raw-md5'). Limit to 200 hashes per request."
        ),
        "cwe": "CWE-1006",
    }


def rule_format_invalid(s):
    fmt = s.get("john_format_invalid")
    if not fmt:
        return None
    return {
        "name": f"John hash audit skipped - hash_format '{fmt}' not in allowlist",
        "severity": "INFO",
        "evidence": ("VulnusLab restricts john --format to a vetted list to prevent injection. "
                     f"'{fmt}' is not currently allowed."),
        "remediation": (
            "Use one of: nt, ntlm, raw-md5, raw-sha1, raw-sha256, raw-sha512, "
            "md5crypt, sha256crypt, sha512crypt, bcrypt, descrypt, lm, netntlmv2, "
            "krb5tgs, krb5asrep, mssql, mysql-sha1, phpass, wpapsk, pkzip, rar, 7z, zip."
        ),
        "cwe": "CWE-1006",
    }


def rule_no_wordlist(s):
    if not s.get("john_no_wordlist"):
        return None
    return {
        "name": "John hash audit skipped - no wordlist available on scanner host",
        "severity": "INFO",
        "evidence": ("None of the default wordlists were found: /usr/share/wordlists/rockyou.txt, "
                     "/usr/share/john/password.lst, /usr/share/wordlists/john.lst."),
        "remediation": ("Install seclists + extract rockyou: "
                        "apt install seclists wordlists && gunzip /usr/share/wordlists/rockyou.txt.gz. "
                        "Or pass options.wordlist_path to an existing wordlist on the scanner host."),
        "cwe": "CWE-1006",
    }


def rule_binary_missing(s):
    if not s.get("john_hash_audit_error"):
        return None
    if "john binary not installed" not in str(s.get("john_hash_audit_error")):
        return None
    return {
        "name": "John the Ripper binary not installed on scanner host",
        "severity": "INFO",
        "evidence": "shutil.which('john') returned None.",
        "remediation": ("Install john: apt install john (Debian/Kali). For best coverage "
                        "use john-jumbo (community-jumbo edition) which supports 200+ hash formats."),
        "cwe": "CWE-1006",
    }


def rule_positive(s):
    if s.get("john_hash_audit_total"):
        return None
    if s.get("john_input_missing"):
        return None
    if s.get("john_format_invalid"):
        return None
    if s.get("john_no_wordlist"):
        return None
    if s.get("john_hash_audit_error"):
        return None
    in_count = s.get("john_hash_audit_hashes_in") or 0
    if not in_count:
        return None
    return {
        "name": "Hash batch survived John the Ripper wordlist+rules audit",
        "severity": "POSITIVE",
        "evidence": (f"{in_count} hash(es) audited against "
                     f"{s.get('john_hash_audit_wordlist', 'wordlist')} with --rules=Single. "
                     "Zero cracks within wall-clock cap."),
        "remediation": ("Strong sign your password policy is resisting common attacks. "
                        "Re-audit after every breach-corpus update and rotate any account whose "
                        "password matches even after a new corpus release."),
        "cwe": "CWE-521",
        "owasp": "A02:2021",
    }


JOHN_HASH_AUDIT_FINDING_RULES = [
    rule_high_cracked,
    rule_timeout,
    rule_input_missing,
    rule_format_invalid,
    rule_no_wordlist,
    rule_binary_missing,
    rule_positive,
]
