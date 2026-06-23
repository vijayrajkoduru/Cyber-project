"""kerberoast_audit - finding rules (VL-METHOD aware).

MITRE T1558.003 (Kerberoasting). Reads state populated by the
KerberoastAudit 7-stage scanner:

  - methodology_findings   : list of TGS tickets extracted
  - dc_ip / domain         : target AD context
  - fingerprint            : rootDSE info (functional levels, NCs)
  - spn_accounts_count     : SPN-bearing accounts enumerated
  - kerberoast_tgs_count   : TGS tickets successfully extracted
  - chain_next             : downstream cracker handoffs
  - bind_failed            : LDAP bind failure (creds rejected upstream)
  - impacket_missing       : impacket library not installed
  - skipped_reason         : pre_flight skip reason

Severity model:
  CONFIRMED rc4_crackable + sql_service -> CRITICAL CVSS 9.1
  CONFIRMED rc4_crackable               -> CRITICAL CVSS 8.8
  CONFIRMED aes_crackable               -> HIGH     CVSS 7.2
  SUSPECTED any etype                   -> LOW      CVSS 3.7
  Bind failed (creds bad)               -> HIGH     CVSS 7.5
  Zero SPN accounts                     -> POSITIVE (AD immune)
  Input missing / impacket missing      -> INFO
"""


INTEL_FIELDS = [
    ("Domain Controller",          "dc_ip"),
    ("AD Domain",                  "domain"),
    ("Bind User",                  "bind_user"),
    ("Forest Info",                "fingerprint"),
    ("SPN accounts enumerated",    "spn_accounts_count"),
    ("TGS tickets extracted",      "kerberoast_tgs_count"),
    ("Stage timings (ms)",         "stage_timings"),
    ("Stage errors",               "stage_errors"),
    ("Chain ID",                   "chain_id"),
]


# ── helper: group methodology_findings by privilege + service type ──

def _findings_by_priv_and_type(s):
    """Group methodology_findings into buckets the rules consume:

      confirmed_rc4_sql   - CONFIRMED + rc4_crackable_high_value + sql_service
      confirmed_rc4       - CONFIRMED + rc4_crackable_high_value (any target)
      confirmed_aes       - CONFIRMED + aes_crackable_lower_priority
      confirmed_other     - CONFIRMED + unknown_etype
      suspected           - SUSPECTED (any etype)
    """
    buckets = {
        "confirmed_rc4_sql":   [],
        "confirmed_rc4":       [],
        "confirmed_aes":       [],
        "confirmed_other":     [],
        "suspected":           [],
    }
    for f in (s.get("methodology_findings") or []):
        conf = f.get("confidence", "SUSPECTED")
        priv = f.get("privilege", "")
        priv_target = f.get("privilege_target", "")
        if conf == "CONFIRMED":
            if priv == "rc4_crackable_high_value" and priv_target == "sql_service":
                buckets["confirmed_rc4_sql"].append(f)
            if priv == "rc4_crackable_high_value":
                buckets["confirmed_rc4"].append(f)
            elif priv == "aes_crackable_lower_priority":
                buckets["confirmed_aes"].append(f)
            else:
                buckets["confirmed_other"].append(f)
        else:
            buckets["suspected"].append(f)
    return buckets


# ── INFO rules: scan didn't run for input/env reasons ───────────────

def rule_input_missing(s):
    reason = (s.get("skipped_reason") or "").lower()
    if "requires ad user" not in reason:
        return None
    return {
        "name": "Kerberoasting audit skipped - required inputs missing",
        "severity": "INFO",
        "evidence": (
            "Scanner needs an authenticated AD context to request "
            "service tickets. Supply on request body options: "
            "dc_ip (domain controller IP), domain (e.g. corp.local), "
            "user (any domain user - need NOT be admin), and either "
            "password OR nt_hash. The audit then enumerates SPN-bearing "
            "accounts via LDAP and requests TGS tickets via Kerberos."),
        "remediation": (
            "Provide options.dc_ip, options.domain, options.user, and "
            "options.password (or options.nt_hash for pass-the-hash). "
            "Any low-privilege domain user account is sufficient - "
            "Kerberoasting works because TGS-REP issuance is a feature, "
            "not a privilege check."),
        "cwe": "CWE-1006",
    }


def rule_dc_unreachable(s):
    reason = (s.get("skipped_reason") or "").lower()
    if "kerberos" not in reason and "not reachable" not in reason:
        return None
    if "requires ad user" in reason:
        return None  # handled by rule_input_missing
    return {
        "name": "Domain Controller Kerberos port (88/TCP) unreachable",
        "severity": "INFO",
        "evidence": s.get("skipped_reason") or "DC TCP/88 unreachable",
        "remediation": (
            "Confirm dc_ip resolves to the actual DC and TCP/88 is "
            "reachable from the scanner host. Re-run once Kerberos "
            "is reachable to actually perform the audit."),
        "cwe": "CWE-1006",
    }


def rule_impacket_missing(s):
    if not s.get("impacket_missing"):
        return None
    return {
        "name": "impacket library not installed - Kerberoasting cannot run",
        "severity": "INFO",
        "evidence": (
            "tools/password/tier3_ad/kerberoast_audit.py requires the "
            "impacket Python library (krb5.kerberosv5, krb5.types, "
            "krb5.constants). Container image was built without it."),
        "remediation": (
            "Add `pip install impacket>=0.11` to the Dockerfile + rebuild "
            "the backend image. Verify with `python -c 'import impacket'`."),
        "cwe": "CWE-1006",
    }


def rule_bind_failed(s):
    if not s.get("bind_failed"):
        return None
    return {
        "name": "LDAP bind to Domain Controller failed - chained credentials rejected",
        "severity": "HIGH", "cvss": "7.5",
        "cwe": "CWE-287", "owasp": "A07:2021",
        "evidence": (
            "The supplied AD credentials could not bind to the DC's "
            "LDAP service. This typically means: (a) chained credentials "
            "from an upstream scanner have since been rotated or "
            "disabled, (b) the user account is locked out from prior "
            "brute-force activity, or (c) the password was correct for a "
            "different DC/domain. The Kerberoasting audit cannot proceed "
            "without a valid authenticated context."),
        "remediation": (
            "Re-supply valid AD credentials via options.user + "
            "options.password (or options.nt_hash). If credentials came "
            "from an upstream ldap_brute or similar scanner, verify the "
            "account is still active and unlocked. Check DC event logs "
            "(Security 4625/4740) for the exact bind failure reason."),
    }


def rule_zero_spn_accounts(s):
    # Only fire if pre_flight + fingerprint succeeded but no SPNs exist
    if s.get("skipped_reason"):
        return None
    if s.get("impacket_missing") or s.get("bind_failed"):
        return None
    if s.get("spn_accounts_count") is None:
        return None
    if int(s.get("spn_accounts_count") or 0) > 0:
        return None
    return {
        "name": "Zero SPN-bearing accounts found - AD is immune to Kerberoasting",
        "severity": "POSITIVE",
        "evidence": (
            "LDAP enumeration with filter "
            "(&(samAccountType=805306368)(servicePrincipalName=*)) "
            "returned ZERO user accounts with registered SPNs. "
            "Kerberoasting (T1558.003) requires a user account (not a "
            "machine account) to have at least one SPN so an attacker "
            "can request a TGS encrypted with that account's NTLM hash. "
            "With no such accounts, the entire attack vector is "
            "unavailable in this domain."),
        "remediation": (
            "Maintain this hygiene: continue registering service SPNs "
            "against MACHINE accounts (computer$ objects) only, never "
            "against regular user accounts. If a service genuinely needs "
            "a user-context SPN, use a Group Managed Service Account "
            "(gMSA) so the password is rotated automatically and is "
            "120+ chars long (computationally infeasible to crack)."),
        "cwe": "CWE-521",
        "owasp": "A07:2021",
    }


# ── CONFIRMED Kerberoasting findings (grouped) ──────────────────────

def rule_confirmed_sql_service(s):
    b = _findings_by_priv_and_type(s)
    sql = b["confirmed_rc4_sql"]
    if not sql:
        return None
    accounts = ", ".join(f.get("spn_account", "?") for f in sql[:5])
    # ZERO-FP severity: extracting an RC4 TGS proves the ticket is RC4-encrypted,
    # NOT that the password is crackable. Crack time depends entirely on the
    # service-account password policy - a 20+ char random / gMSA password is
    # uncrackable even with RC4. CRITICAL only when a weak service-account
    # password policy is CONFIRMED; otherwise HIGH (real, but crackability
    # unproven).
    weak_confirmed = bool(s.get("weak_password_policy_confirmed"))
    sev = "CRITICAL" if weak_confirmed else "HIGH"
    cvss = "9.1" if weak_confirmed else "8.1"
    name_prefix = "CRITICAL" if weak_confirmed else "HIGH"
    policy_note = (
        " A weak service-account password policy was CONFIRMED for this domain, "
        "so the RC4 ticket is expected to be crackable offline."
        if weak_confirmed else
        " NOTE: crack time depends on the service-account password policy - an "
        "RC4 ticket protected by a 20+ char random or gMSA password (auto-rotated "
        "240 chars) is computationally infeasible to crack. Severity is HIGH "
        "(not CRITICAL) until a weak service-account password policy is confirmed.")
    return {
        "name": (f"{name_prefix}: SQL service account TGS extracted - "
                 f"{len(sql)} ticket(s), RC4-crackable"),
        "severity": sev, "cvss": cvss,
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": (
            f"Extracted RC4-HMAC-encrypted TGS tickets for SQL "
            f"service accounts (MSSQLSvc/*). Compromise of these "
            f"accounts grants database-level access AND a foothold "
            f"on the SQL host (xp_cmdshell + service account "
            f"privileges = SYSTEM in most deployments). RC4 hashes "
            f"crack on a single GPU at ~5,000 H/s for hashcat -m "
            f"13100 - an 8-char mixed-case password cracks in under "
            f"24 hours.{policy_note} Accounts: {accounts}. MITRE T1558.003 "
            f"(Kerberoasting) -> T1078.002 (Domain Accounts) -> "
            f"T1059.003 (cmd via xp_cmdshell). Verification: "
            f"hashcat -m 13100 format validated."),
        "remediation": (
            "1. Migrate SQL service accounts to gMSA "
            "(Group Managed Service Accounts) immediately - 240-char "
            "auto-rotating passwords are computationally uncrackable. "
            "2. If gMSA migration is blocked, rotate the affected "
            "service account passwords to 28+ char random strings "
            "TODAY and force AES-only encryption (msDS-Supported"
            "EncryptionTypes = 0x18 - excludes RC4). "
            "3. Audit SQL Server roles/permissions held by these "
            "accounts; revoke sysadmin if assigned. "
            "4. Enable advanced auditing on the DC: "
            "Audit Kerberos Service Ticket Operations -> Success+"
            "Failure. Hunt for event 4769 with TicketEncryption"
            "Type=0x17 (RC4) to detect future Kerberoasting."),
    }


def rule_confirmed_rc4_kerberoast(s):
    b = _findings_by_priv_and_type(s)
    rc4 = b["confirmed_rc4"]
    # Avoid double-counting: rule_confirmed_sql_service handles the
    # SQL subset. Surface non-SQL RC4 here.
    non_sql = [f for f in rc4 if f.get("privilege_target") != "sql_service"]
    if not non_sql:
        return None
    accounts = ", ".join(f.get("spn_account", "?") for f in non_sql[:5])
    # ZERO-FP severity: see rule_confirmed_sql_service. An RC4 ticket is only
    # offline-crackable in practice when the service-account password is weak.
    # CRITICAL only when a weak password policy is CONFIRMED; otherwise HIGH.
    weak_confirmed = bool(s.get("weak_password_policy_confirmed"))
    sev = "CRITICAL" if weak_confirmed else "HIGH"
    cvss = "8.8" if weak_confirmed else "7.5"
    policy_note = (
        " A weak service-account password policy was CONFIRMED, so these RC4 "
        "tickets are expected to be crackable offline."
        if weak_confirmed else
        " NOTE: crack time depends on the service-account password policy - RC4 "
        "tickets protected by 20+ char random or gMSA passwords are infeasible "
        "to crack. Severity is HIGH (not CRITICAL) until a weak service-account "
        "password policy is confirmed.")
    return {
        "name": (f"Kerberoasting RC4-HMAC TGS tickets extracted - "
                 f"{len(non_sql)} account(s), offline-crackable"),
        "severity": sev, "cvss": cvss,
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": (
            f"Extracted TGS-REP tickets encrypted with RC4-HMAC "
            f"(etype 23) for {len(non_sql)} service account(s) on "
            f"{s.get('domain', 'the domain')}. RC4 tickets are the "
            f"fastest-cracking Kerberoasting target: hashcat -m 13100 "
            f"hits ~5,000 H/s on a single mid-tier GPU (RTX 3060), "
            f"~80,000 H/s on an RTX 4090. An 8-character mixed-case "
            f"service password cracks in under 24 hours; rockyou/"
            f"hashcat rules complete in minutes.{policy_note} Accounts: {accounts}. "
            f"MITRE T1558.003. Verification: hashcat -m 13100 ticket "
            f"format validated."),
        "remediation": (
            "1. Identify each affected service account (sAMAccountName "
            "above). 2. Migrate to gMSA where possible (auto-rotated "
            "240-char passwords). 3. For accounts that cannot migrate, "
            "set msDS-SupportedEncryptionTypes = 0x18 (AES-128+AES-256 "
            "only, no RC4) and rotate the password to a 28+ char random "
            "string. 4. Enable DC event 4769 audit + alert on "
            "TicketEncryptionType=0x17 (RC4) requests - any RC4 TGS "
            "request after AES enforcement is anomalous. 5. Hunt "
            "historically for prior Kerberoasting in 4769 logs."),
    }


def rule_confirmed_aes_kerberoast(s):
    b = _findings_by_priv_and_type(s)
    aes = b["confirmed_aes"]
    if not aes:
        return None
    accounts = ", ".join(f.get("spn_account", "?") for f in aes[:5])
    return {
        "name": (f"Kerberoasting AES TGS tickets extracted - "
                 f"{len(aes)} account(s), offline-crackable (slower)"),
        "severity": "HIGH", "cvss": "7.2",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": (
            f"Extracted TGS-REP tickets encrypted with AES "
            f"(etype 17 AES128 or 18 AES256) for {len(aes)} service "
            f"account(s). AES is 50-100x slower to crack than RC4 - "
            f"hashcat -m 19700 hits ~50-100 H/s on a single GPU - but "
            f"still tractable for weak passwords. A 9-char common-"
            f"dictionary password cracks in days; brute force is "
            f"infeasible above 12 random chars. Accounts: {accounts}. "
            f"Even AES Kerberoasting is a real risk if password policy "
            f"allows short or dictionary-based service passwords."),
        "remediation": (
            "1. Enforce 28+ char random passwords on all service "
            "accounts (or migrate to gMSA which gives you 240 chars "
            "for free). 2. Set strong password policy: Fine-Grained "
            "Password Policy (FGPP) targeted at service accounts: "
            "min 25 chars, complexity required, no dictionary words. "
            "3. Monitor DC 4769 events for TGS request bursts from a "
            "single user (Kerberoasting tools usually request all "
            "tickets back-to-back). 4. Disable RC4 entirely "
            "(msDS-SupportedEncryptionTypes excludes 0x4) to force "
            "AES-only and remove the easier crack target."),
    }


def rule_suspected_kerberoast(s):
    b = _findings_by_priv_and_type(s)
    suspected = b["suspected"]
    if not suspected:
        return None
    return {
        "name": (f"SUSPECTED Kerberoasting tickets - "
                 f"{len(suspected)} extracted but format unvalidated"),
        "severity": "LOW", "cvss": "3.7",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": (
            f"The scanner extracted {len(suspected)} ticket "
            f"response(s) but the hashcat -m 13100 format check "
            f"failed (truncated, malformed, or unexpected etype). "
            f"This can happen when the DC returns an error response, "
            f"the account is disabled/locked, or impacket version "
            f"skew. Treat as informational until verified manually."),
        "remediation": (
            "Re-run the scan to confirm reproducibility. If tickets "
            "still appear SUSPECTED, manually validate the raw hash "
            "format against a known-good Kerberoasting reference (e.g. "
            "Impacket GetUserSPNs.py output). If the format is in fact "
            "valid, treat at the appropriate CONFIRMED severity."),
    }


def rule_chain_handoff(s):
    chain_next = s.get("chain_next") or []
    if not chain_next:
        return None
    return {
        "name": "Cross-scanner chain handoff suggested",
        "severity": "INFO",
        "evidence": (
            "Extracted TGS tickets enable downstream offline cracking "
            "and follow-on lateral movement. Chain handoff next: " +
            ", ".join(chain_next) + ". The john_hash_audit scanner "
            "consumes the hashcat-formatted ticket strings directly."),
        "remediation": (
            "Re-run with chain_id propagation to automatically follow "
            "up with: " + ", ".join(chain_next) + ". The VL-METHOD "
            "chaining engine will spawn these with the captured "
            "ticket hashes via the cross-scanner pipeline."),
        "cwe": "CWE-1006",
    }


KERBEROAST_AUDIT_FINDING_RULES = [
    rule_input_missing,
    rule_dc_unreachable,
    rule_impacket_missing,
    rule_bind_failed,
    rule_zero_spn_accounts,
    rule_confirmed_rc4_kerberoast,
    rule_confirmed_aes_kerberoast,
    rule_confirmed_sql_service,
    rule_suspected_kerberoast,
    rule_chain_handoff,
]
