"""dcsync_audit - finding rules (VL-METHOD aware).

DCSync (MITRE T1003.006) is the technique of abusing Active Directory's
DRSUAPI / GetNCChanges replication API to extract password hashes
WITHOUT touching the DC's filesystem or running code on the DC. Any
principal granted DS-Replication-Get-Changes + DS-Replication-Get-
Changes-All extended-rights on the domain object can replicate the
domain naming context and walk away with every NT hash in the directory
- including krbtgt.

This scanner is the BLUE-TEAM proof-of-concept variant:

  - Default behavior dumps ONLY krbtgt as a single-account sample to
    prove DCSync is exploitable. Customer can then act on the finding
    without us holding their full domain hash file.
  - options.full_dump=True opt-in unlocks a full domain dump (capped at
    10000 entries) for customers who explicitly requested it as part of
    their statement of work.

State keys this rules file reads (populated by DcsyncAudit's 7 stages):
  - has_dcsync_rights         : bool from quick_probe ldap ACE check
  - krbtgt_hash_extracted     : bool from deep_scan
  - dcsync_hashes_extracted   : int  count from deep_scan
  - bind_failed               : bool from fingerprint
  - impacket_missing          : bool from import time
  - methodology_findings      : list of verified hash findings
  - chain_next                : downstream scanner names

Severity ladder:
  CONFIRMED krbtgt extracted          -> CRITICAL CVSS 10.0  (golden-ticket capable)
  CONFIRMED user-pop hash dump        -> CRITICAL CVSS 9.8   (full domain compromise)
  CONFIRMED regular user dump only    -> HIGH     CVSS 8.1   (offline crack risk)
  SUSPECTED ACE rights but no extract -> MEDIUM   CVSS 5.3   (manual confirm)
  bind_failed                          -> HIGH     CVSS 7.5   (perimeter LDAP exposed)
  no DCSync rights (correct posture)  -> POSITIVE
"""


INTEL_FIELDS = [
    ("Domain Controller",         "dc_ip"),
    ("AD Domain",                 "domain"),
    ("Bind User",                 "bind_user"),
    ("Forest Info",               "fingerprint"),
    ("DCSync rights detected",    "has_dcsync_rights"),
    ("Hashes extracted",          "dcsync_hashes_extracted"),
    ("krbtgt hash extracted",     "krbtgt_hash_extracted"),
    ("Stage timings (ms)",        "stage_timings"),
    ("Stage errors",              "stage_errors"),
    ("Chain ID",                  "chain_id"),
]


# ═══════════════════════════════════════════════════════════════════
#  Skip / input-missing rules (INFO severity)
# ═══════════════════════════════════════════════════════════════════


def rule_input_missing(s):
    reason = s.get("skipped_reason") or ""
    if "requires AD admin user" not in reason:
        return None
    return {
        "name": "DCSync audit skipped - AD admin credentials not supplied",
        "severity": "INFO",
        "evidence": ("This scanner needs an authenticated AD context "
                     "(options.dc_ip + options.domain + options.user + "
                     "options.password/nt_hash) to test DCSync rights. "
                     "Without that, no replication ACE check is possible. "
                     f"Reason reported: {reason}"),
        "remediation": ("Re-run the scan with options.dc_ip (domain controller IP), "
                        "options.domain (e.g. corp.local), options.user, and "
                        "options.password OR options.nt_hash. This scanner is "
                        "designed for authenticated AD assessments only."),
        "cwe": "CWE-1006",
    }


def rule_dc_unreachable(s):
    reason = s.get("skipped_reason") or ""
    if not ("LDAP" in reason or "SMB" in reason):
        return None
    if "unreachable" not in reason.lower():
        return None
    return {
        "name": "Domain Controller LDAP/SMB unreachable - DCSync test skipped",
        "severity": "INFO",
        "evidence": (f"The supplied DC IP did not accept TCP/389 (LDAP) or TCP/445 "
                     f"(SMB - needed for DRSUAPI). DCSync abuses MS-DRSR over SMB, "
                     f"so both ports must be reachable from the scanner. "
                     f"Reason: {reason}"),
        "remediation": ("Confirm options.dc_ip is correct, the DC is online, and "
                        "your scanner host can reach 389/tcp + 445/tcp on it. "
                        "If this is a perimeter scan, DCSync isn't testable "
                        "remotely anyway - re-run from an internal vantage."),
        "cwe": "CWE-1006",
    }


def rule_impacket_missing(s):
    if not s.get("impacket_missing"):
        return None
    return {
        "name": "impacket library missing - DCSync proof-of-capability not run",
        "severity": "INFO",
        "evidence": ("The Python impacket library (impacket.examples.secretsdump) "
                     "is required for the DRSUAPI extraction step. It was not "
                     "importable in this scanner container. The ACE-check stage "
                     "(LDAP) may still have run if other deps were present."),
        "remediation": ("Install impacket: `pip install impacket` (typically already "
                        "in the VulnusLab backend image). If you see this in "
                        "production, the backend image is missing a dependency - "
                        "raise a Dockerfile fix."),
        "cwe": "CWE-1006",
    }


def rule_bind_failed(s):
    if not s.get("bind_failed"):
        return None
    return {
        "name": "LDAP bind to Domain Controller failed - credentials rejected or LDAP locked down",
        "severity": "HIGH", "cvss": "7.5",
        "cwe": "CWE-287", "owasp": "A07:2021",
        "evidence": ("The supplied AD user could not bind to the DC over LDAP. "
                     "Possible causes: (1) wrong password / nt_hash, "
                     "(2) account locked or disabled, (3) LDAP signing required "
                     "+ scanner sent simple bind, (4) channel binding enforced. "
                     "No DCSync ACE check or hash extraction could be performed."),
        "remediation": ("Verify the supplied credentials authenticate normally "
                        "(e.g. `ldapsearch -x -H ldap://DC -D user@domain -W`). "
                        "If LDAP signing is mandated (RECOMMENDED), the scanner "
                        "should use LDAPS or SASL-bound LDAP for the audit. "
                        "Mandatory LDAP signing IS the correct hardening posture - "
                        "do not weaken it just to make this scanner work."),
    }


# ═══════════════════════════════════════════════════════════════════
#  POSITIVE rule - no DCSync rights = correct least-privilege posture
# ═══════════════════════════════════════════════════════════════════


def rule_no_dcsync_rights(s):
    if s.get("bind_failed"):
        return None
    if s.get("has_dcsync_rights") is not False:
        return None
    bind_user = s.get("bind_user") or "(unknown)"
    domain = s.get("domain") or "(unknown)"
    return {
        "name": "Supplied user does NOT have DCSync rights - correct least-privilege posture",
        "severity": "POSITIVE",
        "evidence": (f"LDAP ACE inspection on the domain object for {domain} "
                     f"confirms {bind_user} (and the groups it belongs to) does "
                     f"not hold DS-Replication-Get-Changes / "
                     f"DS-Replication-Get-Changes-All extended rights. The "
                     f"account therefore cannot perform a DCSync attack. This "
                     f"is the correct least-privilege posture."),
        "remediation": ("Continue restricting these replication rights to Domain "
                        "Controllers + the explicit AD recovery service accounts. "
                        "Periodically audit nTSecurityDescriptor on the domain NC "
                        "head to make sure no new principals were granted these "
                        "rights (BloodHound's `GetChangesAll` query is ideal for "
                        "ongoing monitoring)."),
        "cwe": "CWE-269",
        "owasp": "A01:2021",
    }


# ═══════════════════════════════════════════════════════════════════
#  Helper: group methodology_findings by privilege classification
# ═══════════════════════════════════════════════════════════════════


def _findings_by_priv(s):
    """Bucket methodology_findings by privilege_level (set in Stage 6)."""
    out = {
        "golden_ticket_capable": [],
        "domain_admin_compromise": [],
        "computer_account_compromise": [],
        "user_credential_dump": [],
        "suspected": [],
    }
    for f in (s.get("methodology_findings") or []):
        conf = f.get("confidence", "SUSPECTED")
        priv = f.get("privilege_level", "")
        if conf != "CONFIRMED":
            out["suspected"].append(f)
            continue
        if priv == "golden_ticket_capable":
            out["golden_ticket_capable"].append(f)
        elif priv == "domain_admin_compromise":
            out["domain_admin_compromise"].append(f)
        elif priv == "computer_account_compromise":
            out["computer_account_compromise"].append(f)
        else:
            out["user_credential_dump"].append(f)
    return out


# ═══════════════════════════════════════════════════════════════════
#  CONFIRMED findings - krbtgt / capability / user dump
# ═══════════════════════════════════════════════════════════════════


def rule_confirmed_krbtgt_extracted(s):
    g = _findings_by_priv(s)
    if not g["golden_ticket_capable"]:
        return None
    sample = g["golden_ticket_capable"][0]
    return {
        "name": "CRITICAL: DCSync proven - krbtgt account hash extracted (Golden Ticket capability)",
        "severity": "CRITICAL", "cvss": "10.0",
        "cwe": "CWE-269", "owasp": "A01:2021",
        "evidence": ("krbtgt is the AD service account whose NT hash signs every "
                     "Kerberos TGT in the domain. Possession of its NT hash lets "
                     "an attacker forge arbitrary Kerberos tickets (Golden Ticket) "
                     "impersonating ANY user, including Domain Admins, with a "
                     "10-year default lifetime. Extraction was performed via "
                     "impacket DRSUAPI GetNCChanges (MS-DRSR). "
                     f"Hash marker: {sample.get('hash_marker', '(redacted)')}. "
                     "This is full-domain compromise."),
        "remediation": ("IMMEDIATELY: (1) Audit which principals hold replication "
                        "rights on the domain NC (`Get-ADObject 'DC=corp,DC=local' "
                        "-Properties nTSecurityDescriptor`). Strip anything that "
                        "isn't a DC or the explicit AD recovery service. "
                        "(2) Rotate the krbtgt password TWICE with at least 10 "
                        "hours between rotations (single rotation leaves the "
                        "previous hash valid; two invalidates any pre-existing "
                        "golden tickets). (3) Audit Kerberos TGT issuance for "
                        "the last 30 days. (4) Assume the source host that "
                        "performed the DCSync is compromised - rebuild from "
                        "known-good media. (5) Long-term: enable Protected Users + "
                        "constrained-delegation hygiene, deploy Tier-0 admin model."),
    }


def rule_confirmed_dcsync_capable(s):
    g = _findings_by_priv(s)
    # Fires when DCSync extracted Domain Admin or computer account hashes
    # but krbtgt itself was not part of the sample (e.g. customer ran with
    # full_dump=True and the rule above already covered krbtgt).
    if g["golden_ticket_capable"]:
        return None
    targets = g["domain_admin_compromise"] + g["computer_account_compromise"]
    if not targets:
        return None
    sample_users = ", ".join(f.get("account_name", "?") for f in targets[:5])
    return {
        "name": (f"CRITICAL: DCSync proven - {len(targets)} privileged "
                 f"account hash(es) extracted from DC"),
        "severity": "CRITICAL", "cvss": "9.8",
        "cwe": "CWE-269", "owasp": "A01:2021",
        "evidence": ("The supplied AD user successfully replicated privileged "
                     "account secrets from the Domain Controller via "
                     "DRSUAPI/GetNCChanges (MITRE T1003.006). This means full "
                     "domain compromise is one offline crack away (or "
                     "immediately, if pass-the-hash is viable against the "
                     "target service). "
                     f"Sample accounts: {sample_users}. "
                     "Note: krbtgt itself was not in this sample - re-running "
                     "with options.full_dump=True would extract it."),
        "remediation": ("(1) Revoke the replication rights from the principal "
                        "used in this test - it should NOT hold "
                        "DS-Replication-Get-Changes on the domain NC. "
                        "(2) Rotate the exposed account passwords. "
                        "(3) Deploy honey-token replication detection (Microsoft "
                        "Defender for Identity flags DRSUAPI from non-DC sources). "
                        "(4) Enforce Tier-0 admin model so no normal user can "
                        "accumulate DCSync rights via group nesting."),
    }


def rule_confirmed_user_dump(s):
    g = _findings_by_priv(s)
    if g["golden_ticket_capable"] or g["domain_admin_compromise"]:
        return None  # higher-severity rule already covers
    if not g["user_credential_dump"]:
        return None
    n = len(g["user_credential_dump"])
    sample = ", ".join(f.get("account_name", "?") for f in g["user_credential_dump"][:5])
    return {
        "name": f"HIGH: DCSync extracted {n} regular user hash(es) from AD",
        "severity": "HIGH", "cvss": "8.1",
        "cwe": "CWE-269", "owasp": "A01:2021",
        "evidence": ("Regular AD user account hashes were extracted via DCSync. "
                     "These are NT hashes (and possibly LM hashes for legacy "
                     "accounts) that can be cracked offline with hashcat / john. "
                     "Cracked passwords often work on other services (VPN, SaaS, "
                     "external mail) due to password reuse. "
                     f"Sample accounts: {sample}."),
        "remediation": ("(1) Remove DCSync rights from non-DC principals - the "
                        "current grant is too broad. "
                        "(2) Force a password reset on the exposed accounts. "
                        "(3) Enable AD password-policy hashing best practices "
                        "(disable LM hash storage via NoLMHash policy if not "
                        "already done). "
                        "(4) Roll out PHS / AD password protection to block "
                        "weak passwords at change-time."),
    }


def rule_suspected_dcsync(s):
    g = _findings_by_priv(s)
    if g["golden_ticket_capable"] or g["domain_admin_compromise"] or g["user_credential_dump"]:
        return None
    if not g["suspected"]:
        return None
    n = len(g["suspected"])
    return {
        "name": (f"MEDIUM: DCSync ACE rights detected but extraction not "
                 f"confirmed ({n} indicator)"),
        "severity": "MEDIUM", "cvss": "5.3",
        "cwe": "CWE-269", "owasp": "A01:2021",
        "evidence": ("LDAP ACE inspection shows the supplied user (or a group "
                     "they belong to) has DS-Replication-Get-Changes / "
                     "DS-Replication-Get-Changes-All on the domain NC, but the "
                     "DRSUAPI extraction stage did not complete successfully "
                     "(library error, timeout, or extraction skipped because "
                     "options.full_dump was False AND krbtgt-only probe also "
                     "failed). The capability is present - exploitation is "
                     "likely possible but not yet proven in this run."),
        "remediation": ("Manually verify by running `secretsdump.py -just-dc-user "
                        "krbtgt domain/user:pwd@dc-ip` from an authorized host. "
                        "If extraction works, treat as CRITICAL (rule above) and "
                        "rotate krbtgt + revoke the replication grant. If "
                        "extraction fails despite the ACE being present, the DC "
                        "may have additional protections (e.g. AD CS, Defender "
                        "for Identity blocking) - document and move on."),
    }


# ═══════════════════════════════════════════════════════════════════
#  Chain handoff INFO
# ═══════════════════════════════════════════════════════════════════


def rule_chain_handoff(s):
    chain_next = s.get("chain_next") or []
    if not chain_next:
        return None
    return {
        "name": "Cross-scanner chain handoff suggested",
        "severity": "INFO",
        "evidence": ("DCSync findings unlock the following downstream scanners: " +
                     ", ".join(chain_next)),
        "remediation": ("These chain-next scanners (when implemented) will "
                        "inherit the extracted credentials/hashes and continue "
                        "the attack path automatically: " +
                        ", ".join(chain_next) + ". "
                        "Until then, manually run the equivalent post-DCSync "
                        "tradecraft (golden-ticket forge / pass-the-hash lateral "
                        "movement / DPAPI unmask)."),
        "cwe": "CWE-1006",
    }


DCSYNC_AUDIT_FINDING_RULES = [
    rule_input_missing,
    rule_dc_unreachable,
    rule_impacket_missing,
    rule_bind_failed,
    rule_no_dcsync_rights,
    rule_confirmed_krbtgt_extracted,
    rule_confirmed_dcsync_capable,
    rule_confirmed_user_dump,
    rule_suspected_dcsync,
    rule_chain_handoff,
]
