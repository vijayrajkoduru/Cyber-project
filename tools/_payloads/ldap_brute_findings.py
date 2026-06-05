"""ldap_brute - finding rules (VL-METHOD aware).

Built 2026-06-05 for the VL-METHOD methodology pattern. Reads state
keys populated by LdapBrute's 7-stage flow:
  - methodology_findings  : list of verified credentials
  - port_reachable        : bool from pre_flight
  - fingerprint           : dict {vendor_name, vendor_version,
                                   supported_ldap_versions,
                                   naming_contexts,
                                   anonymous_bind_allowed,
                                   supported_sasl_mechanisms,
                                   has_starttls, error}
  - anonymous_bind_allowed: bool shortcut
  - chain_next            : list of follow-up scanner names

Severity matrix (confidence + privilege_level):
  CONFIRMED admin (Domain/Enterprise/Schema Admin) -> CRITICAL CVSS 9.8
  CONFIRMED user                                    -> MEDIUM   CVSS 6.5
  CONFIRMED guest                                   -> LOW      CVSS 4.3
  SUSPECTED any                                     -> LOW      CVSS 3.7

INDEPENDENT findings (fire regardless of credential outcome):
  Anonymous bind allowed -> HIGH CVSS 7.5 (CWE-287)
  No StartTLS on 389     -> MEDIUM CVSS 5.3 (CWE-319)
"""


# ════════════════════════════════════════════════════════════════════
#  Intel fields surfaced into the PDF "Scanner Intel" panel
# ════════════════════════════════════════════════════════════════════

INTEL_FIELDS = [
    ("LDAP Server Info",          "fingerprint"),
    ("Quick-probe attempts",      "quick_probe_attempts"),
    ("Quick-probe hits",          "quick_probe_hits"),
    ("Deep scan attempts",        "ldap_deep_attempts"),
    ("Stage timings (ms)",        "stage_timings"),
    ("Stage errors",              "stage_errors"),
    ("Chain ID",                  "chain_id"),
]


# ════════════════════════════════════════════════════════════════════
#  Helpers
# ════════════════════════════════════════════════════════════════════


def _findings_by_severity(s):
    """Bucket methodology_findings by computed severity."""
    out = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for f in (s.get("methodology_findings") or []):
        conf = f.get("confidence", "SUSPECTED")
        priv = f.get("privilege_level", "unknown")
        if conf == "CONFIRMED":
            if priv == "admin":    out["CRITICAL"].append(f)
            elif priv == "user":   out["MEDIUM"].append(f)
            elif priv == "guest":  out["LOW"].append(f)
            else:                   out["LOW"].append(f)
        else:
            out["LOW"].append(f)
    return out


def _ldap_responded(s) -> bool:
    """True if LDAP rootDSE actually returned a real server response.
    A stateful firewall can accept TCP/389 without LDAP running, in
    which case naming_contexts + vendor_name are empty. Guards the
    POSITIVE finding from lying."""
    fp = s.get("fingerprint") or {}
    if fp.get("vendor_name"):
        return True
    nc = fp.get("naming_contexts") or []
    return bool(nc)


def _fp_blurb(s) -> str:
    fp = s.get("fingerprint") or {}
    parts = []
    if fp.get("vendor_name"):    parts.append(f"vendor={fp['vendor_name']}")
    if fp.get("vendor_version"): parts.append(f"version={fp['vendor_version']}")
    nc = fp.get("naming_contexts") or []
    if nc:
        parts.append(f"naming_contexts={nc[0]}"
                     + (f" (+{len(nc)-1} more)" if len(nc) > 1 else ""))
    if fp.get("has_starttls"):   parts.append("StartTLS=yes")
    else:                         parts.append("StartTLS=no")
    return ", ".join(parts) or "fingerprint unavailable"


# ════════════════════════════════════════════════════════════════════
#  Rules
# ════════════════════════════════════════════════════════════════════


def rule_unreachable(s):
    if s.get("port_reachable") is not False:
        return None
    return {
        "name": "LDAP port unreachable - cannot test directory credential security",
        "severity": "INFO",
        "evidence": s.get("skipped_reason") or "Port 389 closed or filtered",
        "remediation": ("If LDAP is meant to be exposed (Active Directory / "
                        "OpenLDAP), verify firewall + slapd / NTDS is "
                        "running. If LDAP is intentionally blocked from this "
                        "scan origin, that is excellent hardening - LDAP "
                        "should NEVER be exposed to the public internet. "
                        "Re-run scan from an internal vantage point to test "
                        "credential strength."),
        "cwe": "CWE-1006",
    }


def rule_lib_missing(s):
    if not s.get("ldap3_lib_missing"):
        return None
    return {
        "name": "ldap3 Python library missing - LDAP credential audit skipped",
        "severity": "INFO",
        "evidence": ("The ldap3 library is required for this scanner. "
                     "The Python ldap3 package was not found in the runtime "
                     "image. Install with `pip install ldap3` in the backend "
                     "Dockerfile."),
        "remediation": ("Add 'ldap3' to backend Dockerfile pip install layer "
                        "and rebuild. Verify with "
                        "`python -c \"import ldap3; print(ldap3.__version__)\"` "
                        "inside the container."),
        "cwe": "CWE-1006",
    }


def rule_input_missing(s):
    # Only fires when pre_flight succeeded but customer didn't provide
    # userlist/passlist for deep_scan. Quick-probe still ran against the
    # 5 known defaults regardless.
    deep_skipped = s.get("deep_skipped") or ""
    if "userlist/passlist not supplied" not in deep_skipped:
        return None
    if s.get("methodology_total", 0) > 0:
        return None
    return {
        "name": "Deep LDAP spray skipped - userlist/passlist not provided",
        "severity": "INFO",
        "evidence": ("Quick-probe ran 5 known-bad LDAP defaults (cn=admin/admin, "
                     "Administrator/Administrator, admin/admin, cn=manager/manager, "
                     "guest/guest) - none worked. To run a full spray, provide "
                     "options.userlist + options.passlist on the request body "
                     "(newline-separated). Max 10 users x 25 passwords."),
        "remediation": ("Supply options.userlist + options.passlist to test "
                        "against your AD password policy. Recommend SecLists "
                        "top-5 Windows usernames + breach top-20 passwords."),
        "cwe": "CWE-1006",
    }


def rule_anonymous_bind_allowed(s):
    """INDEPENDENT high-severity finding - fires when anonymous bind is
    permitted, regardless of credential spray outcome."""
    if not s.get("anonymous_bind_allowed"):
        return None
    return {
        "name": "LDAP allows anonymous binds - directory open to unauthenticated enumeration",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-287",
        "owasp": "A07:2021",
        "evidence": ("LDAP allows anonymous binds - any unauthenticated "
                     "attacker can enumerate directory objects, users, groups, "
                     "computer names, GPO information, and (on misconfigured "
                     "AD) SPN values for offline kerberoasting. "
                     f"Server: {_fp_blurb(s)}."),
        "remediation": (
            "1. Active Directory: set GPO 'Network access: Allow anonymous "
            "SID/Name translation' = Disabled. Set 'dsHeuristics' 7th "
            "character to 0 in CN=Directory Service,CN=Windows NT,CN="
            "Services,CN=Configuration to forbid anonymous LDAP queries. "
            "2. OpenLDAP: add `disallow bind_anon` and `require authc` to "
            "slapd.conf (or cn=config olcDisallows: bind_anon). "
            "3. 389 Directory Server: set nsslapd-allow-anonymous-access "
            "= rootdse (rootDSE only, not subtree). "
            "4. Block TCP/389 + 636 at the perimeter - LDAP should never "
            "be reachable from the public internet."
        ),
    }


def rule_no_starttls(s):
    """INDEPENDENT medium-severity finding - LDAP/389 reachable but server
    does not advertise StartTLS, meaning binds traverse the wire in
    cleartext."""
    if s.get("port_reachable") is not True:
        return None
    fp = s.get("fingerprint") or {}
    if fp.get("error"):
        return None
    # Only fire if we actually got rootDSE data - otherwise we don't know
    if not _ldap_responded(s):
        return None
    if fp.get("has_starttls"):
        return None
    return {
        "name": "LDAP transmits credentials in cleartext - StartTLS not advertised",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-319",
        "owasp": "A02:2021",
        "evidence": ("LDAP server on TCP/389 does not advertise the StartTLS "
                     "extension (OID 1.3.6.1.4.1.1466.20037) in its rootDSE. "
                     "Simple-bind credentials traverse the network in "
                     "cleartext and can be captured by any on-path attacker "
                     f"(ARP spoof, switch SPAN, malicious VLAN). Server: "
                     f"{_fp_blurb(s)}."),
        "remediation": (
            "1. Enable LDAPS (TCP/636) with a valid certificate. AD: "
            "install an Enterprise CA cert on every DC. "
            "2. Require StartTLS for all 389 binds. OpenLDAP: "
            "`olcSecurity: tls=1`. AD: set GPO 'Domain controller: LDAP "
            "server signing requirements' = Require signing + 'LDAP "
            "client signing requirements' = Require signing on clients. "
            "3. Audit binds via Event ID 2887 + 2889 to find clients "
            "still using cleartext simple-bind."
        ),
    }


def rule_positive_quick(s):
    """Quick-probe ran, NO hits, NO real findings - GOOD signal.
    Guard: only fire POSITIVE if LDAP rootDSE actually responded."""
    if s.get("methodology_total", 0) > 0:
        return None
    if s.get("port_reachable") is not True:
        return None
    if s.get("quick_probe_attempts", 0) == 0:
        return None
    if not _ldap_responded(s):
        return None  # filtered/no-service -> rule_inconclusive
    return {
        "name": "LDAP rejects all 5 known-bad default credentials",
        "severity": "POSITIVE",
        "evidence": (f"Tried {s.get('quick_probe_attempts', 5)} known-bad LDAP "
                     "defaults (cn=admin/admin, Administrator/Administrator, "
                     "admin/admin, cn=manager/manager, guest/guest); "
                     f"all rejected. Server: {_fp_blurb(s)}."),
        "remediation": ("Continue blocking default credentials. Enforce 14+ "
                        "char GPO password policy (or `pwdMinLength` on "
                        "OpenLDAP password policy overlay). Require StartTLS "
                        "/ LDAPS so credential checks cannot be sniffed. "
                        "Disable anonymous binds."),
        "cwe": "CWE-521",
        "owasp": "A07:2021",
    }


def rule_inconclusive(s):
    """Port accepts TCP SYN but rootDSE returned nothing - typical of
    stateful firewall 'accept-and-RST' or non-LDAP service on 389."""
    if s.get("methodology_total", 0) > 0:
        return None
    if s.get("port_reachable") is not True:
        return None
    if s.get("quick_probe_attempts", 0) == 0:
        return None
    if _ldap_responded(s):
        return None
    fp_err = (s.get("fingerprint") or {}).get("error") or "no rootDSE data parsed"
    return {
        "name": "LDAP port reachable but service did not respond to rootDSE - credential security UNVERIFIED",
        "severity": "INFO",
        "evidence": (f"TCP/389 accepted the connection but the LDAP rootDSE "
                     f"read returned no usable data ({fp_err}) and "
                     f"{s.get('quick_probe_attempts', 5)} default-credential "
                     "bind attempts all errored/timed-out. This is typical "
                     "of stateful firewalls that 'accept-and-RST' filtered "
                     "ports, or a non-LDAP service squatting on 389. We "
                     "cannot claim credentials are strong - we never reached "
                     "the LDAP auth layer."),
        "remediation": ("If this host is supposed to expose LDAP, verify "
                        "slapd / NTDS is running and the firewall isn't "
                        "intercepting the connection. Re-run scan from an "
                        "internal vantage point. If LDAP is intentionally "
                        "filtered at the perimeter, that is excellent "
                        "hardening - LDAP should never be exposed to the "
                        "public internet."),
        "cwe": "CWE-1006",
    }


def rule_confirmed_admin(s):
    g = _findings_by_severity(s)
    if not g["CRITICAL"]:
        return None
    users = ", ".join(sorted({f.get("user", "?") for f in g["CRITICAL"]}))[:200]
    chain = s.get("chain_next") or []
    chain_blurb = ""
    if chain:
        chain_blurb = (" Cross-scanner chain will follow up with: "
                       + ", ".join(chain) + ".")
    return {
        "name": f"CONFIRMED Domain/Enterprise/Schema Admin LDAP access via password ({len(g['CRITICAL'])} account)",
        "severity": "CRITICAL", "cvss": "9.8",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": ("Privileged AD account(s) compromised via LDAP password "
                     "spray. memberOf includes Domain Admins / Enterprise "
                     "Admins / Schema Admins - attacker has full Active "
                     "Directory takeover capability (DCSync, Golden Ticket, "
                     "persistence via AdminSDHolder). Verified by separate "
                     "ldap3 bind + search (verification_method="
                     f"ldap3_second_bind_search). Compromised users: {users}. "
                     f"Server: {_fp_blurb(s)}.{chain_blurb}"),
        "remediation": (
            "CRITICAL - treat the entire AD forest as compromised until proven clean. "
            "1. Immediately rotate the password for the compromised privileged account AND krbtgt twice (back-to-back) to invalidate Golden Tickets. "
            "2. Audit Windows Event ID 4624 (logon type 3) + 4672 (privileged logon) + 4768/4769 (Kerberos) + 4742 (computer account change) for prior unauthorized access. "
            "3. Run BloodHound + impacket-secretsdump and confirm no Mimikatz / DCSync / AdminSDHolder backdoors. Look for unexpected SIDHistory entries. "
            "4. Enforce 14+ char password policy + Protected Users group + 'Account is sensitive and cannot be delegated' on Tier 0 accounts. "
            "5. Require smartcard + Windows Hello for Business for all admin logons. "
            "6. Disable simple-bind over cleartext (require StartTLS / LDAPS) and forbid anonymous binds. "
            "7. Block TCP/389 + 636 at the perimeter - LDAP must never be exposed to the public internet. "
            "8. Follow up with the chained scanners ad_bloodhound_audit, kerberoast_audit, asreproast_audit, post_exploit_ad_persistence to confirm no remaining attacker footholds."
        ),
    }


def rule_confirmed_user(s):
    g = _findings_by_severity(s)
    if not g["MEDIUM"]:
        return None
    users = ", ".join(sorted({f.get("user", "?") for f in g["MEDIUM"]}))[:200]
    return {
        "name": f"CONFIRMED regular user LDAP access via password ({len(g['MEDIUM'])} account)",
        "severity": "MEDIUM", "cvss": "6.5",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": ("Regular user account(s) compromised via LDAP spray. No "
                     "Domain Admin / Enterprise Admin / Schema Admin group "
                     "membership found, but attacker has a foothold for "
                     "kerberoasting, ASREPRoasting, AD recon (BloodHound), "
                     "and lateral movement attempts. Verified by separate "
                     f"ldap3 bind + search. Compromised users: {users}. "
                     f"Server: {_fp_blurb(s)}."),
        "remediation": ("Force password reset on the affected accounts and "
                        "notify owner(s). Enforce password complexity (14+ "
                        "chars, no breach-corpus matches) via GPO password "
                        "policy. Consider rolling out Windows Hello / "
                        "smartcard auth. Require StartTLS / LDAPS so future "
                        "binds aren't sniffed in cleartext. Forbid anonymous "
                        "binds so users cannot be enumerated."),
    }


def rule_confirmed_guest(s):
    g = _findings_by_severity(s)
    guest_low = [f for f in g["LOW"]
                 if f.get("confidence") == "CONFIRMED"
                 and f.get("privilege_level") == "guest"]
    if not guest_low:
        return None
    return {
        "name": f"CONFIRMED guest/restricted LDAP access enabled ({len(guest_low)} account)",
        "severity": "LOW", "cvss": "4.3",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": ("Guest / minimally-privileged LDAP account is enabled. "
                     "Bind succeeded but search was blocked (no read perm "
                     "on the directory tree). Still useful for an attacker "
                     "as a low-noise probe and pivot. "
                     f"Server: {_fp_blurb(s)}."),
        "remediation": ("Disable the guest LDAP account. For AD: "
                        "`Disable-ADAccount -Identity guest`. For OpenLDAP: "
                        "remove the account from cn=config or set "
                        "userPassword to a 32-char random value. Forbid "
                        "anonymous + null-credential binds explicitly."),
    }


def rule_suspected(s):
    g = _findings_by_severity(s)
    suspected = [f for f in g["LOW"] if f.get("confidence") == "SUSPECTED"]
    if not suspected:
        return None
    users = ", ".join(sorted({f.get("user", "?") for f in suspected}))[:200]
    return {
        "name": f"SUSPECTED LDAP credential ({len(suspected)} - needs manual verification)",
        "severity": "LOW", "cvss": "3.7",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": ("Initial bind appeared to succeed but the ldap3 second-"
                     "bind verification could not confirm directory read. "
                     "Could be a transient network issue, an account with "
                     "bind-but-no-read, or a server returning unsolicited "
                     f"notice mid-session. Users: {users}."),
        "remediation": ("Manually verify with `ldapsearch -x -H ldap://<host> "
                        "-D '<dn>' -w '<pwd>' -b '<base_dn>' '(objectClass=*)'"
                        "`. If auth + search DO work, treat as CONFIRMED "
                        "MEDIUM/CRITICAL per privilege. If auth fails, this "
                        "was a false positive - safe to ignore but file an "
                        "issue for VulnusLab to tune ldap3 verification."),
    }


def rule_chain_handoff(s):
    chain_next = s.get("chain_next") or []
    if not chain_next:
        return None
    return {
        "name": "Cross-scanner chain handoff suggested",
        "severity": "INFO",
        "evidence": ("Confirmed LDAP credentials enable downstream scanners: "
                     + ", ".join(chain_next)),
        "remediation": ("Re-run scan with chain_id propagation to automatically "
                        "follow up with: " + ", ".join(chain_next) + ". These "
                        "will inherit the captured credentials via the "
                        "VL-METHOD chaining engine and pursue AD enumeration "
                        "/ kerberoasting / persistence artifacts."),
        "cwe": "CWE-1006",
    }


LDAP_BRUTE_FINDING_RULES = [
    rule_unreachable,
    rule_lib_missing,
    rule_input_missing,
    rule_anonymous_bind_allowed,
    rule_no_starttls,
    rule_positive_quick,
    rule_inconclusive,
    rule_confirmed_admin,
    rule_confirmed_user,
    rule_confirmed_guest,
    rule_suspected,
    rule_chain_handoff,
]
