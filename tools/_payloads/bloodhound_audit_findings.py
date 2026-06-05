"""bloodhound_audit - finding rules (VL-METHOD aware).

Reads state keys populated by BloodhoundAudit's 7-stage flow:
  - methodology_findings  : list of AD attack paths
  - bind_failed           : bool, LDAP bind failure
  - bloodhound_missing    : bool, bloodhound-python not installed
  - bh_user_count / bh_computer_count / bh_group_count / bh_domain_admin_count
  - ad_attack_paths_count : total attack paths found
  - chain_next            : list of follow-up scanner names

Severity mapping (per path_type):
  CONFIRMED krbtgt_compromise_path    -> CRITICAL 9.4 (unconstrained delegation)
  CONFIRMED da_via_kerberoast         -> CRITICAL 9.1
  CONFIRMED da_via_asreproast         -> CRITICAL 9.1
  CONFIRMED da_via_acl_abuse          -> HIGH 8.1
  CONFIRMED domain_admin_reachable    -> HIGH 8.1
  SUSPECTED any                       -> LOW 3.7
"""


INTEL_FIELDS = [
    ("Domain Controller",     "dc_ip"),
    ("AD Domain",             "domain"),
    ("Bind User",             "bind_user"),
    ("Forest Info",           "fingerprint"),
    ("Users enumerated",      "bh_user_count"),
    ("Computers enumerated",  "bh_computer_count"),
    ("Groups enumerated",     "bh_group_count"),
    ("Domain Admins",         "bh_domain_admin_count"),
    ("Attack paths found",    "ad_attack_paths_count"),
    ("Stage timings (ms)",    "stage_timings"),
    ("Stage errors",          "stage_errors"),
    ("Chain ID",              "chain_id"),
]


# ── helpers ──────────────────────────────────────────────────────────


def _findings_by_path_type(s, path_types):
    """Return methodology_findings whose path_type is in path_types AND
    confidence == CONFIRMED."""
    if isinstance(path_types, str):
        path_types = (path_types,)
    out = []
    for f in (s.get("methodology_findings") or []):
        if f.get("confidence") != "CONFIRMED":
            continue
        if f.get("path_type") in path_types:
            out.append(f)
    return out


def _suspected_findings(s):
    out = []
    for f in (s.get("methodology_findings") or []):
        if f.get("confidence") == "SUSPECTED":
            out.append(f)
    return out


# ── rules ────────────────────────────────────────────────────────────


def rule_input_missing(s):
    reason = (s.get("skipped_reason") or "").lower()
    if "requires" not in reason:
        return None
    return {
        "name": "BloodHound audit skipped - required input missing",
        "severity": "INFO",
        "evidence": s.get("skipped_reason") or "Missing dc_ip / domain / user / password",
        "remediation": ("Provide options.dc_ip, options.domain, options.user, and "
                        "options.password (or options.nt_hash). ANY authenticated "
                        "domain user can run the collection - no Domain Admin "
                        "needed."),
        "cwe": "CWE-1006",
    }


def rule_dc_unreachable(s):
    reason = (s.get("skipped_reason") or "").lower()
    if "ldap" not in reason and "smb" not in reason and "unreachable" not in reason:
        return None
    return {
        "name": "Domain Controller unreachable - cannot enumerate AD",
        "severity": "INFO",
        "evidence": s.get("skipped_reason") or "LDAP/389 or SMB/445 not reachable on DC",
        "remediation": ("Verify the dc_ip is correct and LDAP/389 + SMB/445 are "
                        "reachable from the scanner. If the DC is firewalled, run "
                        "the scan from an internal vantage. If LDAP is intentionally "
                        "blocked at the perimeter, that is good hardening."),
        "cwe": "CWE-1006",
    }


def rule_bloodhound_missing(s):
    if not s.get("bloodhound_missing"):
        return None
    return {
        "name": "bloodhound-python library not installed - cannot collect AD graph",
        "severity": "INFO",
        "evidence": ("The 'bloodhound' Python package is not importable in the "
                     "backend container. AD graph collection requires this library "
                     "to query LDAP and build the attack-path graph."),
        "remediation": ("Install bloodhound-python: pip install bloodhound. "
                        "Re-run scan after install."),
        "cwe": "CWE-1006",
    }


def rule_bind_failed(s):
    if not s.get("bind_failed"):
        return None
    return {
        "name": "LDAP bind to Domain Controller FAILED - supplied creds invalid or DC rejects bind",
        "severity": "HIGH", "cvss": "7.5",
        "cwe": "CWE-287",
        "evidence": ("LDAP simple/NTLM bind to the DC failed with the supplied "
                     "user/password (or NT hash). Either the credentials are "
                     "incorrect, the account is disabled/locked, or LDAP signing/"
                     "channel-binding is enforced and rejecting our bind. "
                     "Without a successful bind we cannot enumerate the AD graph."),
        "remediation": ("Verify the supplied user has Active Directory account + "
                        "the password/hash is current. If LDAP signing + channel "
                        "binding are enforced (good!), supply a Kerberos ticket "
                        "via options.kerberos_ccache instead of plaintext."),
    }


def rule_too_many_domain_admins(s):
    n = int(s.get("bh_domain_admin_count") or 0)
    if n <= 5:
        return None
    return {
        "name": f"Excessive Domain Admin accounts ({n}) - violates least privilege",
        "severity": "MEDIUM", "cvss": "5.3",
        "cwe": "CWE-269",
        "evidence": (f"The Domain Admins group contains {n} members (transitive). "
                     "Industry guidance (NIST SP 800-53 AC-6, Microsoft Tier-0 "
                     "model) recommends <=5 dedicated Tier-0 admin accounts. "
                     "Every additional DA account expands the attack surface for "
                     "Kerberoast / AS-REP roast / password spray / phishing."),
        "remediation": ("Audit Domain Admins membership. Move daily-driver "
                        "accounts to Tier-1/2 groups. Adopt the Microsoft tiered "
                        "admin model: Tier-0 (DA/EA/Schema) dedicated accounts, "
                        "Tier-1 server admins separate, Tier-2 workstation admins "
                        "separate. Enforce just-in-time admin via PIM/PAM."),
    }


def rule_clean_graph(s):
    if s.get("bind_failed"):
        return None
    if int(s.get("ad_attack_paths_count") or 0) > 0:
        return None
    if not s.get("fingerprint"):
        return None  # bind didn't succeed, can't claim clean
    return {
        "name": "No attack paths to Domain Admin identified from this user's perspective",
        "severity": "POSITIVE",
        "evidence": ("BloodHound graph analysis from the supplied user's vantage "
                     f"point enumerated {s.get('bh_user_count', 0)} users, "
                     f"{s.get('bh_computer_count', 0)} computers, "
                     f"{s.get('bh_group_count', 0)} groups and found ZERO attack "
                     "paths leading to Domain Admin. No Kerberoastable DAs, no "
                     "AS-REP roastable DAs, no shadow-admin ACL paths, no "
                     "unconstrained delegation hosts."),
        "remediation": ("Maintain current hardening. Re-run BloodHound quarterly "
                        "or after major AD changes (new GPOs, new admin groups, "
                        "ACL delegations). Consider running collection from "
                        "additional low-privileged user vantages to validate the "
                        "clean result holistically."),
        "cwe": "CWE-269",
        "owasp": "A01:2021",
    }


def rule_confirmed_unconstrained_delegation(s):
    paths = _findings_by_path_type(s, "krbtgt_compromise_path")
    if not paths:
        return None
    hosts = sorted({p.get("source_node") or p.get("target_node") or "?" for p in paths})[:5]
    return {
        "name": f"CONFIRMED unconstrained delegation host(s) - krbtgt compromise launchpad ({len(paths)} path)",
        "severity": "CRITICAL", "cvss": "9.4",
        "cwe": "CWE-269", "owasp": "A01:2021",
        "evidence": ("Computer account(s) flagged with TRUSTED_FOR_DELEGATION "
                     "(unconstrained Kerberos delegation). Any user who "
                     "authenticates to these hosts forwards their TGT - if a "
                     "Domain Admin or krbtgt-equivalent ever touches the host, "
                     "an attacker with local admin can extract the TGT from "
                     "lsass and forge a Golden Ticket. Affected hosts: " +
                     ", ".join(hosts)),
        "remediation": ("Replace unconstrained delegation with CONSTRAINED + "
                        "PROTOCOL_TRANSITION delegation (resource-based "
                        "constrained delegation is preferred since Server 2012). "
                        "Add high-value accounts (DA, krbtgt, service accounts) "
                        "to the 'Protected Users' group and flag them as 'Account "
                        "is sensitive and cannot be delegated'. Audit which "
                        "service requires delegation - most don't actually need "
                        "it."),
    }


def rule_confirmed_da_via_kerberoast(s):
    paths = _findings_by_path_type(s, "kerberoastable_da")
    if not paths:
        return None
    users = sorted({p.get("source_node") or "?" for p in paths})[:5]
    return {
        "name": f"CONFIRMED Domain Admin reachable via Kerberoasting ({len(paths)} path)",
        "severity": "CRITICAL", "cvss": "9.1",
        "cwe": "CWE-294", "owasp": "A07:2021",
        "evidence": ("Domain Admin account(s) have a Service Principal Name "
                     "(SPN) registered, making them Kerberoastable. ANY "
                     "authenticated domain user can request a service ticket "
                     "for these accounts and crack the ticket offline (hashcat "
                     "-m 13100). With weak passwords, full DA compromise is "
                     "minutes away. Affected DA accounts: " +
                     ", ".join(users)),
        "remediation": ("Remove SPNs from Domain Admin accounts - DAs should "
                        "NEVER run services. Move service accounts to a "
                        "dedicated tier with random 128-character managed "
                        "passwords (Group Managed Service Accounts / gMSA). "
                        "If a DA-with-SPN is unavoidable, enforce 25+ char "
                        "complex passphrase rotated monthly. Audit with "
                        "Get-ADUser -Filter {AdminCount -eq 1 -and "
                        "ServicePrincipalName -ne '$null'}."),
    }


def rule_confirmed_da_via_asreproast(s):
    paths = _findings_by_path_type(s, "asreproastable_da")
    if not paths:
        return None
    users = sorted({p.get("source_node") or "?" for p in paths})[:5]
    return {
        "name": f"CONFIRMED Domain Admin reachable via AS-REP Roasting ({len(paths)} path)",
        "severity": "CRITICAL", "cvss": "9.1",
        "cwe": "CWE-294", "owasp": "A07:2021",
        "evidence": ("Domain Admin account(s) have UF_DONT_REQUIRE_PREAUTH set "
                     "(Kerberos pre-authentication disabled). ANY UNAUTHENTICATED "
                     "attacker who knows the username can request an AS-REP "
                     "response and crack it offline (hashcat -m 18200). No "
                     "valid credential needed to start the attack. Affected DA "
                     "accounts: " + ", ".join(users)),
        "remediation": ("IMMEDIATELY enable Kerberos pre-authentication on these "
                        "accounts (uncheck 'Do not require Kerberos preauth' in "
                        "ADUC). Pre-auth disabled is virtually never needed in "
                        "modern AD - it's a legacy flag from NT4 trusts. Audit "
                        "with Get-ADUser -Filter {DoesNotRequirePreAuth -eq "
                        "$True}."),
    }


def rule_confirmed_da_via_acl(s):
    paths = _findings_by_path_type(s, "shadow_admin_path")
    if not paths:
        return None
    sources = sorted({p.get("source_node") or "?" for p in paths})[:5]
    return {
        "name": f"CONFIRMED shadow admin via ACL abuse ({len(paths)} path)",
        "severity": "HIGH", "cvss": "8.1",
        "cwe": "CWE-269", "owasp": "A01:2021",
        "evidence": ("Non-DA principal(s) hold dangerous ACL rights "
                     "(GenericAll / GenericWrite / WriteDacl / WriteOwner / "
                     "ForceChangePassword) on Domain Admin objects. These "
                     "'shadow admins' can take over a real DA account at any "
                     "time without being members of the DA group - bypassing "
                     "normal Tier-0 auditing. Affected principals: " +
                     ", ".join(sources)),
        "remediation": ("Audit ACLs on DA objects with PowerView's "
                        "Get-ObjectAcl or BloodHound's 'Outbound Object "
                        "Control' query. Remove dangerous rights from "
                        "non-Tier-0 principals. Document each remaining "
                        "delegation in writing. Enable 4670/4662 ACL-change "
                        "auditing on the Domain Admins OU."),
    }


def rule_confirmed_da_reachable(s):
    paths = _findings_by_path_type(s, "domain_admin_path")
    if not paths:
        return None
    sources = sorted({p.get("source_node") or "?" for p in paths})[:5]
    return {
        "name": f"CONFIRMED graph path from owned user to Domain Admin ({len(paths)} path)",
        "severity": "HIGH", "cvss": "8.1",
        "cwe": "CWE-269", "owasp": "A01:2021",
        "evidence": ("BloodHound BFS traversal found at least one edge-chain "
                     "starting from the supplied (owned) user and ending at a "
                     "Domain Admin account. This means the current vantage "
                     "user can escalate to DA through a series of group "
                     "memberships, ACL grants, or session hops. Source "
                     "nodes: " + ", ".join(sources)),
        "remediation": ("Review each edge in the path and break the weakest "
                        "link. Common kills: remove the user from over-broad "
                        "nested groups; revoke ACL grants on DA objects; "
                        "deploy LAPS so local-admin sessions can't be re-used "
                        "across hosts. Re-run BloodHound after each change to "
                        "confirm the path is gone."),
    }


def rule_suspected_attack_path(s):
    sus = _suspected_findings(s)
    if not sus:
        return None
    return {
        "name": f"SUSPECTED AD attack path ({len(sus)} - needs manual verification)",
        "severity": "LOW", "cvss": "3.7",
        "cwe": "CWE-269", "owasp": "A01:2021",
        "evidence": ("Graph analysis flagged candidate attack paths but LDAP "
                     "edge re-validation could not confirm at least one edge "
                     "(e.g. group membership had churned between collection "
                     "and re-check, or the user/group was renamed). These "
                     "paths may still be exploitable - they should be "
                     "manually verified with PowerView or live BloodHound."),
        "remediation": ("Re-run the BloodHound collection (the AD state may "
                        "have shifted between collection and verification). "
                        "If the path persists, treat as CONFIRMED HIGH and "
                        "remediate the underlying edge."),
    }


def rule_chain_handoff(s):
    chain_next = s.get("chain_next") or []
    if not chain_next:
        return None
    return {
        "name": "Cross-scanner chain handoff suggested",
        "severity": "INFO",
        "evidence": ("Discovered AD attack paths enable downstream scanners: " +
                     ", ".join(chain_next)),
        "remediation": ("Re-run scan with chain_id propagation to automatically "
                        "follow up with: " + ", ".join(chain_next) + ". "
                        "These will inherit the discovered attack path "
                        "metadata via the VL-METHOD chaining engine."),
        "cwe": "CWE-1006",
    }


BLOODHOUND_AUDIT_FINDING_RULES = [
    rule_input_missing,
    rule_dc_unreachable,
    rule_bloodhound_missing,
    rule_bind_failed,
    rule_too_many_domain_admins,
    rule_clean_graph,
    rule_confirmed_unconstrained_delegation,
    rule_confirmed_da_via_kerberoast,
    rule_confirmed_da_via_asreproast,
    rule_confirmed_da_via_acl,
    rule_confirmed_da_reachable,
    rule_suspected_attack_path,
    rule_chain_handoff,
]
