"""asreproast_audit - finding rules (VL-METHOD aware).

AS-REP Roasting (MITRE T1558.004) targets AD accounts with the
UF_DONT_REQUIRE_PREAUTH flag (4194304). Such accounts will respond to
an unauthenticated AS-REQ with an AS-REP containing material encrypted
with the account's password-derived key - which is offline-crackable
(hashcat -m 18200 / john --format=krb5asrep).

Key differentiator vs Kerberoasting (T1558.003): this scanner does NOT
require credentials - the attack works pre-auth. Any user that can talk
to TCP/88 (Kerberos) can collect AS-REP hashes for misconfigured
accounts.

Severity model:
  krbtgt roastable      -> CRITICAL CVSS 10.0 (must never happen)
  admin roastable       -> CRITICAL CVSS 9.1
  service roastable     -> HIGH     CVSS 7.5
  user roastable        -> MEDIUM   CVSS 6.5
  SUSPECTED (bad hash)  -> LOW      CVSS 3.7
  anonymous LDAP bind   -> HIGH     CVSS 7.5  (independent finding)
"""


INTEL_FIELDS = [
    ("Domain Controller", "dc_ip"),
    ("AD Domain", "domain"),
    ("Anonymous Bind Allowed", "anonymous_bind_allowed"),
    ("Forest Info", "fingerprint"),
    ("Users tested for AS-REP", "asrep_users_tested"),
    ("AS-REP roastable accounts", "asrep_roastable_count"),
    ("Stage timings (ms)", "stage_timings"),
    ("Stage errors", "stage_errors"),
    ("Chain ID", "chain_id"),
]


# ── INFO / skip rules ────────────────────────────────────────────────


def rule_input_missing(s):
    reason = s.get("skipped_reason") or ""
    if "requires dc_ip + domain" not in reason:
        return None
    return {
        "name": "AS-REP Roasting scan skipped - dc_ip + domain not provided",
        "severity": "INFO",
        "evidence": ("AS-REP Roasting (MITRE T1558.004) needs a Domain "
                     "Controller IP and the AD domain name to query. "
                     "Supply options.dc_ip and options.domain on the "
                     "request body to enable the audit."),
        "remediation": ("Re-run with options.dc_ip=<DC IP> and "
                        "options.domain=<AD domain, e.g. corp.local>. "
                        "Optionally provide options.userlist to constrain "
                        "the test set."),
        "cwe": "CWE-1006",
    }


def rule_dc_unreachable(s):
    reason = s.get("skipped_reason") or ""
    if "Kerberos" not in reason and "kerberos" not in reason:
        return None
    return {
        "name": "Kerberos service on Domain Controller unreachable",
        "severity": "INFO",
        "evidence": (f"TCP/88 on {s.get('dc_ip') or 'the supplied DC'} did "
                     "not accept a connection. AS-REP Roasting cannot be "
                     "tested without Kerberos reachability. Skipped reason: "
                     + reason),
        "remediation": ("If this DC is meant to be reachable from the scan "
                        "vantage, verify firewall + KDC service. If "
                        "Kerberos is intentionally filtered from this "
                        "network segment, that is good network "
                        "segmentation."),
        "cwe": "CWE-1006",
    }


def rule_impacket_missing(s):
    if not s.get("impacket_missing"):
        return None
    return {
        "name": "impacket library missing - AS-REP Roasting audit could not run",
        "severity": "INFO",
        "evidence": ("The impacket Python library is required to craft the "
                     "raw Kerberos AS-REQ packets used by this audit. It "
                     "was not importable in this backend image."),
        "remediation": ("Install impacket in the backend container: "
                        "`pip install impacket`. The library is already "
                        "listed in the standard Dockerfile - if missing, "
                        "this is a build regression."),
        "cwe": "CWE-1006",
    }


# ── Anonymous LDAP bind (independent finding) ────────────────────────


def rule_anonymous_bind_allowed(s):
    if not s.get("anonymous_bind_allowed"):
        return None
    fp = s.get("fingerprint") or {}
    naming = ", ".join((fp.get("naming_contexts") or [])[:3]) or "n/a"
    return {
        "name": "Active Directory allows anonymous LDAP bind - user enumeration possible",
        "severity": "HIGH", "cvss": "7.5",
        "cwe": "CWE-287", "owasp": "A07:2021",
        "evidence": ("Domain Controller "
                     f"{s.get('dc_ip') or 'unknown'} accepted an anonymous "
                     "LDAP bind to TCP/389. An unauthenticated attacker can "
                     "enumerate every user account, group, and computer "
                     "object in the directory without credentials - "
                     "perfect input for password sprays, AS-REP Roasting, "
                     "and Kerberoasting. "
                     f"Naming contexts visible: {naming}. "
                     f"DC host name: {fp.get('dns_host_name') or 'unknown'}."),
        "remediation": ("Disable anonymous LDAP queries on every Domain "
                        "Controller. Set the LDAP server policy: "
                        "`dsHeuristics` 7th character to '0' (default) "
                        "instead of '2'. Verify with: ldapsearch -x -H "
                        "ldap://<DC> -s base -b '' (should reject anon). "
                        "Re-test by running this scanner after the change "
                        "- anonymous_bind_allowed should drop to False."),
    }


# ── Positive (no roastable accounts) ─────────────────────────────────


def rule_zero_roastable(s):
    tested = s.get("asrep_users_tested", 0)
    roastable = s.get("asrep_roastable_count", 0)
    if tested <= 0:
        return None
    if roastable != 0:
        return None
    return {
        "name": "No AS-REP roastable accounts detected",
        "severity": "POSITIVE",
        "evidence": (f"Tested {tested} account(s) against the Domain "
                     f"Controller {s.get('dc_ip') or 'unknown'} - none "
                     "responded with an AS-REP. All accounts correctly "
                     "require Kerberos pre-authentication "
                     "(UF_DONT_REQUIRE_PREAUTH=4194304 flag NOT set). "
                     "The directory is immune to MITRE T1558.004 against "
                     "the accounts scanned."),
        "remediation": ("Maintain the current configuration. Audit any "
                        "future account creation for the "
                        "'Do not require Kerberos preauthentication' "
                        "checkbox in ADUC (it should remain UNchecked). "
                        "Consider periodic re-scans with a wider userlist "
                        "to catch newly-created vulnerable accounts."),
        "cwe": "CWE-294",
        "owasp": "A07:2021",
    }


# ── Helper: group methodology_findings by privilege ──────────────────


def _findings_by_priv(s):
    out = {
        "domain_root_critical": [],
        "admin_target": [],
        "service_account": [],
        "user": [],
        "suspected": [],
    }
    for f in (s.get("methodology_findings") or []):
        conf = f.get("confidence", "SUSPECTED")
        priv = f.get("privilege_level", "user")
        if conf != "CONFIRMED":
            out["suspected"].append(f)
            continue
        if priv == "domain_root_critical":
            out["domain_root_critical"].append(f)
        elif priv == "admin_target":
            out["admin_target"].append(f)
        elif priv == "service_account":
            out["service_account"].append(f)
        else:
            out["user"].append(f)
    return out


# ── CONFIRMED roastable rules (severity by privilege) ────────────────


def rule_confirmed_krbtgt_roastable(s):
    g = _findings_by_priv(s)
    if not g["domain_root_critical"]:
        return None
    users = ", ".join(f.get("user", "?") for f in g["domain_root_critical"][:5])
    return {
        "name": f"CRITICAL: krbtgt account is AS-REP roastable ({len(g['domain_root_critical'])} hit)",
        "severity": "CRITICAL", "cvss": "10.0",
        "cwe": "CWE-294", "owasp": "A07:2021",
        "evidence": ("The krbtgt account responded to an unauthenticated "
                     "AS-REQ with an AS-REP hash. krbtgt is the Kerberos "
                     "service principal for the entire domain - its hash "
                     "should be UNREACHABLE without DA. This is a "
                     "catastrophic misconfiguration: an offline crack of "
                     "this hash hands the attacker the keys to forge "
                     "Golden Tickets for the entire forest. "
                     f"Account(s): {users}. Verified via hashcat -m 18200 "
                     "format check."),
        "remediation": ("EMERGENCY - immediately uncheck "
                        "'Do not require Kerberos preauthentication' on "
                        "krbtgt in ADUC. Then run `Reset-KrbtgtKeyInteractive` "
                        "TWICE (10 hours apart) to invalidate any tickets "
                        "an attacker may already hold. Audit the domain "
                        "for Golden Ticket indicators (event 4769 with "
                        "encryption type 0x17, anomalous TGT lifetimes). "
                        "Treat the forest as potentially compromised until "
                        "proven clean."),
    }


def rule_confirmed_admin_roastable(s):
    g = _findings_by_priv(s)
    if not g["admin_target"]:
        return None
    users = ", ".join(f.get("user", "?") for f in g["admin_target"][:5])
    return {
        "name": f"CRITICAL: admin account is AS-REP roastable ({len(g['admin_target'])} account)",
        "severity": "CRITICAL", "cvss": "9.1",
        "cwe": "CWE-294", "owasp": "A07:2021",
        "evidence": ("Administrator-level account(s) responded to an "
                     "unauthenticated AS-REQ. The AS-REP contains "
                     "material encrypted with the account's password key, "
                     "which is offline-crackable with hashcat (-m 18200). "
                     "If the password is weak, the attacker gains "
                     "Domain Admin rights without ever touching the wire "
                     "again. "
                     f"Account(s): {users}. Hash format validated."),
        "remediation": ("Uncheck 'Do not require Kerberos preauthentication' "
                        "on each affected account in ADUC (Account tab > "
                        "Account options). Force password reset on the "
                        "affected accounts with a >=20-char passphrase. "
                        "Enable an alert on event ID 4768 with "
                        "PreAuthType=0 to detect future AS-REP roasting "
                        "attempts. Review WHY the flag was set - it is "
                        "almost never required for production accounts."),
    }


def rule_confirmed_service_roastable(s):
    g = _findings_by_priv(s)
    if not g["service_account"]:
        return None
    users = ", ".join(f.get("user", "?") for f in g["service_account"][:5])
    return {
        "name": f"HIGH: service account is AS-REP roastable ({len(g['service_account'])} account)",
        "severity": "HIGH", "cvss": "7.5",
        "cwe": "CWE-294", "owasp": "A07:2021",
        "evidence": ("Service / svc_ account(s) returned an AS-REP without "
                     "pre-authentication. Service accounts typically have "
                     "elevated rights on application servers (database "
                     "writes, file shares, scheduled tasks). An offline "
                     "crack of the AS-REP hash gives the attacker a "
                     "stable, long-lived credential that is rarely "
                     "rotated. "
                     f"Account(s): {users}."),
        "remediation": ("Disable the 'Do not require Kerberos "
                        "preauthentication' flag on each service account. "
                        "Rotate the password (>=25 chars, generated). "
                        "Migrate to a Group Managed Service Account "
                        "(gMSA) where possible - gMSAs cannot be AS-REP "
                        "roasted because their passwords are managed by "
                        "the KDC and never user-known."),
    }


def rule_confirmed_user_roastable(s):
    g = _findings_by_priv(s)
    if not g["user"]:
        return None
    users = ", ".join(f.get("user", "?") for f in g["user"][:5])
    return {
        "name": f"MEDIUM: standard user is AS-REP roastable ({len(g['user'])} account)",
        "severity": "MEDIUM", "cvss": "6.5",
        "cwe": "CWE-294", "owasp": "A07:2021",
        "evidence": ("Standard user account(s) returned AS-REP material "
                     "to an unauthenticated request. The attacker can now "
                     "offline-crack the hash; if the password is weak, "
                     "they obtain a foothold credential for further "
                     "lateral movement and recon (Kerberoasting, "
                     "BloodHound, ADCS abuse). "
                     f"Account(s): {users}."),
        "remediation": ("Uncheck 'Do not require Kerberos preauthentication' "
                        "on each affected account. Notify the account "
                        "owner(s) and enforce a password reset with the "
                        "domain password policy. Confirm the flag was not "
                        "set domain-wide via a misconfigured Group Policy."),
    }


def rule_suspected_asreproast(s):
    g = _findings_by_priv(s)
    if not g["suspected"]:
        return None
    users = ", ".join(f.get("user", "?") for f in g["suspected"][:5])
    return {
        "name": f"SUSPECTED AS-REP material ({len(g['suspected'])} - hash format unverified)",
        "severity": "LOW", "cvss": "3.7",
        "cwe": "CWE-294", "owasp": "A07:2021",
        "evidence": ("Server responded to AS-REQ but returned material "
                     "that did not parse cleanly into hashcat -m 18200 "
                     "format. Could be an enctype the verifier doesn't "
                     "recognize OR a server-side oddity. Manual review "
                     f"recommended. Account(s): {users}."),
        "remediation": ("Manually re-run with impacket GetNPUsers.py "
                        "(`impacket-GetNPUsers <domain>/ -dc-ip <DC> "
                        "-usersfile users.txt -format hashcat`) to "
                        "capture the raw output. If a real AS-REP "
                        "appears, treat as MEDIUM+; if not, the account "
                        "is likely safe."),
    }


# ── Chain handoff ────────────────────────────────────────────────────


def rule_chain_handoff(s):
    chain_next = s.get("chain_next") or []
    if not chain_next:
        return None
    return {
        "name": "Cross-scanner chain handoff suggested",
        "severity": "INFO",
        "evidence": ("Confirmed AS-REP roastable accounts enable downstream "
                     "scanners: " + ", ".join(chain_next) + ". Captured "
                     "hashes feed offline cracking; cracked passwords for "
                     "high-value targets feed DCSync attempts."),
        "remediation": ("Re-run scan with chain_id propagation to "
                        "automatically follow up with: "
                        + ", ".join(chain_next) + ". These will inherit "
                        "the AS-REP hashes via the VL-METHOD chaining "
                        "engine."),
        "cwe": "CWE-1006",
    }


ASREPROAST_AUDIT_FINDING_RULES = [
    rule_input_missing,
    rule_dc_unreachable,
    rule_impacket_missing,
    rule_anonymous_bind_allowed,
    rule_zero_roastable,
    rule_confirmed_krbtgt_roastable,
    rule_confirmed_admin_roastable,
    rule_confirmed_service_roastable,
    rule_confirmed_user_roastable,
    rule_suspected_asreproast,
    rule_chain_handoff,
]
