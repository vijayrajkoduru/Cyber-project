"""medusa_smb_spray - finding rules (VL-METHOD aware).

REWRITTEN 2026-06-05 for the VL-METHOD methodology pattern. Reads new
state keys populated by MedusaSmbSpray's 7-stage flow:
  - methodology_findings  : list of verified credentials (post verify+priv)
  - port_reachable        : bool from pre_flight
  - fingerprint           : dict {server_os, server_name, server_domain,
                                   dialect, signing_required, error}
  - smb_signing_required  : bool surfaced from fingerprint
  - chain_next            : list of follow-up scanner names

Severity matrix (confidence + privilege_level):
  CONFIRMED admin   -> CRITICAL  CVSS 9.8  (C$ writable - full compromise)
  CONFIRMED user    -> MEDIUM    CVSS 6.5  (SMB foothold; needs privesc)
  CONFIRMED guest   -> LOW       CVSS 4.3
  SUSPECTED any     -> LOW       CVSS 3.7  (manual confirm required)

INDEPENDENT findings (fire regardless of credential outcome):
  SMB signing not required -> HIGH CVSS 7.5
      (CWE-345 + CVE-2021-36942 PetitPotam / NTLM relay class)
"""


# ═══════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════


def _findings_by_severity(s):
    """Bucket methodology_findings by computed severity."""
    out = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for f in (s.get("methodology_findings") or []):
        conf = f.get("confidence", "SUSPECTED")
        priv = f.get("privilege_level", "unknown")
        if conf == "CONFIRMED":
            if priv == "admin":        out["CRITICAL"].append(f)
            elif priv == "user":       out["MEDIUM"].append(f)
            elif priv == "guest":      out["LOW"].append(f)
            else:                       out["LOW"].append(f)
        else:
            out["LOW"].append(f)
    return out


def _fp_blurb(s):
    fp = s.get("fingerprint") or {}
    parts = []
    if fp.get("server_os"):     parts.append(f"OS={fp['server_os']}")
    if fp.get("server_name"):   parts.append(f"name={fp['server_name']}")
    if fp.get("server_domain"): parts.append(f"domain={fp['server_domain']}")
    if fp.get("dialect"):       parts.append(f"dialect={fp['dialect']}")
    return ", ".join(parts) or "fingerprint unavailable"


# ═══════════════════════════════════════════════════════════════════
#  Rules
# ═══════════════════════════════════════════════════════════════════


def rule_unreachable(s):
    if s.get("port_reachable") is not False:
        return None
    return {
        "name": "SMB ports unreachable - cannot test SMB credential security",
        "severity": "INFO",
        "evidence": s.get("skipped_reason") or "Ports 445 + 139 both closed or filtered",
        "remediation": ("If SMB is meant to be exposed (file server / domain "
                        "controller), verify firewall + smbd / Server service is "
                        "running. If SMB is intentionally blocked from this scan "
                        "origin, that is the recommended posture - SMB should NEVER "
                        "be exposed to the public internet. Re-run scan from an "
                        "internal vantage point to test SMB credential strength."),
        "cwe": "CWE-1006",
    }


def rule_input_missing(s):
    # Only fires when pre_flight succeeded but no userlist/passlist given.
    # Quick-probe still ran against 5 well-known SMB defaults regardless.
    deep_skipped = s.get("deep_skipped") or ""
    if "userlist/passlist not supplied" not in deep_skipped:
        return None
    if s.get("methodology_total", 0) > 0:
        # quick-probe already found something - don't dilute with INFO
        return None
    return {
        "name": "Deep SMB spray skipped - userlist/passlist not provided",
        "severity": "INFO",
        "evidence": ("Quick-probe ran 5 known-bad SMB defaults "
                     "(Administrator/admin, admin/admin, guest/<empty>, sa/sa, "
                     "root/root) - none worked. To run a full spray, supply "
                     "options.userlist + options.passlist on the request body "
                     "(newline-separated). Max 10 users x 25 pwds."),
        "remediation": ("Supply options.userlist + options.passlist to test "
                        "against your AD password policy. Recommend SecLists "
                        "top-5 Windows usernames + breach top-20 passwords."),
        "cwe": "CWE-1006",
    }


def _fp_responded(s) -> bool:
    """True if SMB negotiation actually got bytes back from a real service.
    Stateful firewalls can accept TCP/445 without SMB running -> dialect /
    server_os / server_name all blank. In that case the POSITIVE rule
    would be lying: we never spoke real SMB, we just timed out 5 times."""
    fp = s.get("fingerprint") or {}
    if fp.get("error"):
        return False
    return bool(fp.get("dialect") or fp.get("server_os")
                or fp.get("server_name") or fp.get("server_domain"))


def rule_positive_quick(s):
    """Quick-probe ran, NO hits, NO real findings - GOOD signal.
    Guard: only fire POSITIVE if SMB negotiation actually parsed a real
    server response. See rule_inconclusive for the 'port reachable but
    no SMB service' branch."""
    if s.get("methodology_total", 0) > 0:
        return None
    if s.get("port_reachable") is not True:
        return None
    if s.get("quick_probe_attempts", 0) == 0:
        return None
    if not _fp_responded(s):
        return None  # filtered/no-service -> rule_inconclusive
    return {
        "name": "SMB rejects all 5 known-bad default credentials",
        "severity": "POSITIVE",
        "evidence": (f"Tried {s.get('quick_probe_attempts', 5)} known-bad SMB "
                     "defaults (Administrator/admin, admin/admin, guest/<empty>, "
                     "sa/sa, root/root); all rejected. "
                     f"Fingerprint: {_fp_blurb(s)}"),
        "remediation": ("Continue blocking default credentials. Enforce 14+ char "
                        "GPO password policy. Disable the local guest account "
                        "(net user guest /active:no). Disable SMBv1 entirely. "
                        "Require SMB signing for all clients."),
        "cwe": "CWE-521",
        "owasp": "A07:2021",
    }


def rule_inconclusive(s):
    """Port accepts TCP SYN but SMB negotiation got no real server data -
    typical of stateful firewalls that 'accept-and-RST' filtered ports,
    or an SMB service that crashed. Emit INFO so PDF doesn't falsely
    claim "SMB rejects defaults" when we never actually spoke SMB."""
    if s.get("methodology_total", 0) > 0:
        return None
    if s.get("port_reachable") is not True:
        return None
    if s.get("quick_probe_attempts", 0) == 0:
        return None
    if _fp_responded(s):
        return None  # service responded -> rule_positive_quick handles it
    fp_err = (s.get("fingerprint") or {}).get("error") or "no SMB dialect parsed"
    return {
        "name": "SMB port reachable but service did not negotiate - credential security UNVERIFIED",
        "severity": "INFO",
        "evidence": (f"TCP/445 accepted the connection but SMB negotiation failed "
                     f"({fp_err}) and {s.get('quick_probe_attempts', 5)} impacket "
                     "default-credential attempts all errored/timed-out. This is "
                     "typical of stateful firewalls that 'accept-and-RST' filtered "
                     "ports, or an SMB service that is hung. We cannot claim "
                     "credentials are strong - we never reached the auth layer."),
        "remediation": ("If this host is supposed to expose SMB, verify smbd / "
                        "Server service is running and the firewall isn't "
                        "intercepting the connection. Re-run scan from an "
                        "internal vantage point. If SMB is intentionally filtered "
                        "at the perimeter, that is excellent hardening - SMB "
                        "should NEVER be exposed to the public internet."),
        "cwe": "CWE-1006",
    }


def rule_lockout_hit(s):
    if not s.get("medusa_lockout_hit"):
        return None
    return {
        "name": "SMB Account Lockout policy is active - reduces brute risk",
        "severity": "POSITIVE",
        "evidence": ("Medusa output reports account lockout / disabled mid-spray. "
                     "This means GPO 'Account lockout threshold' is configured "
                     "and protecting against password brute force."),
        "remediation": ("Account Lockout Policy is doing its job. Keep threshold "
                        "tight (5 fails / 30 min) and monitor Windows Event ID "
                        "4740 to spot password sprays in your SIEM."),
        "cwe": "CWE-307",
    }


def rule_signing_not_required(s):
    """INDEPENDENT high-severity finding - fires when SMB signing is NOT
    required by the server, regardless of credential outcome. This is the
    NTLM-relay attack class (PetitPotam, ShadowCoerce, DFSCoerce, ...)."""
    if s.get("port_reachable") is not True:
        return None
    fp = s.get("fingerprint") or {}
    if fp.get("error"):
        return None  # negotiation failed - we don't know
    sig = s.get("smb_signing_required")
    if sig is None:
        # fall back to fingerprint flag if top-level didn't get surfaced
        sig = fp.get("signing_required")
    if sig is None or sig is True:
        return None
    return {
        "name": "SMB signing NOT required - vulnerable to NTLM relay attacks",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-345",
        "owasp": "A02:2021",
        "evidence": ("SMB negotiation shows server does not require signing "
                     "(isSigningRequired=False). Attackers on the same network "
                     "can coerce authentication (PetitPotam CVE-2021-36942, "
                     "ShadowCoerce, DFSCoerce, PrinterBug) and relay NTLM "
                     "credentials via ntlmrelayx to other hosts/LDAP/ADCS for "
                     f"privilege escalation. Server: {_fp_blurb(s)}."),
        "remediation": (
            "1. Enforce SMB signing on the server. Windows GPO: "
            "'Microsoft network server: Digitally sign communications (always)' = Enabled. "
            "Samba: 'server signing = mandatory' in smb.conf. "
            "2. Enable Extended Protection for Authentication (EPA) on LDAP/ADCS/HTTP services. "
            "3. Disable NTLM where possible; restrict NTLM in GPO and audit Event ID 8001-8004. "
            "4. Block outbound SMB (TCP 445) at the perimeter so coercion attacks can't reach internet attacker hosts. "
            "5. Patch KB5005413 + apply Microsoft's PetitPotam mitigations (CVE-2021-36942)."
        ),
    }


def rule_confirmed_admin(s):
    g = _findings_by_severity(s)
    if not g["CRITICAL"]:
        return None
    users = ", ".join(sorted({f.get("user", "?") for f in g["CRITICAL"]}))[:200]
    return {
        "name": f"CONFIRMED admin SMB access via password ({len(g['CRITICAL'])} account)",
        "severity": "CRITICAL", "cvss": "9.8",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": ("Admin account(s) compromised via SMB password spray. C$ "
                     "share is writable - attacker can drop a service binary or "
                     "scheduled task and gain SYSTEM. Verified by separate "
                     "impacket SMBConnection.login (verification_method="
                     f"impacket_second_login). Compromised users: {users}. "
                     f"Fingerprint: {_fp_blurb(s)}."),
        "remediation": (
            "CRITICAL - treat the host as compromised until proven clean. "
            "1. Rotate the password for the compromised admin account immediately on this host AND every host where the same credentials are reused. "
            "2. Audit Windows Event ID 4624 (logon type 3) + 4672 (privileged logon) + 5145 (share access) for prior unauthorized access. "
            "3. Run impacket-secretsdump + Sysmon to verify no Mimikatz / Cobalt Strike / credential dumping happened. "
            "4. Disable local Administrator account where possible; deploy LAPS for unique per-host local admin passwords. "
            "5. Require MFA for all admin logons (Windows Hello for Business + smartcard for remote sessions). "
            "6. Enforce 14+ char GPO password policy and SMB signing 'always'. "
            "7. Never expose port 445 to the public internet - SMB belongs behind VPN / ZTNA."
        ),
    }


def rule_confirmed_user(s):
    g = _findings_by_severity(s)
    if not g["MEDIUM"]:
        return None
    users = ", ".join(sorted({f.get("user", "?") for f in g["MEDIUM"]}))[:200]
    has_samr = any(f.get("samr_enum_allowed") for f in g["MEDIUM"])
    samr_note = (" Account is allowed to enumerate domain via SAMR over IPC$ - "
                 "useful intel for an attacker to identify high-value targets.") if has_samr else ""
    return {
        "name": f"CONFIRMED regular user SMB access via password ({len(g['MEDIUM'])} account)",
        "severity": "MEDIUM", "cvss": "6.5",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": ("Regular user account(s) compromised via SMB spray. No C$ "
                     "write access (no admin privilege), but attacker has a "
                     "foothold to attempt local privesc, kerberoasting, AD "
                     "enumeration. Verified by second impacket login. "
                     f"Compromised users: {users}.{samr_note} "
                     f"Fingerprint: {_fp_blurb(s)}."),
        "remediation": ("Force password reset on the affected accounts and "
                        "notify owner(s). Enforce password complexity (14+ chars, "
                        "no breach-corpus matches) via GPO. Consider rolling out "
                        "Windows Hello / smartcard auth. Restrict 'Authenticated "
                        "Users' from SAMR remote enumeration: GPO 'Network "
                        "access: Restrict clients allowed to make remote calls "
                        "to SAM' = Administrators only."),
    }


def rule_confirmed_guest(s):
    g = _findings_by_severity(s)
    guest_low = [f for f in g["LOW"]
                 if f.get("confidence") == "CONFIRMED"
                 and f.get("privilege_level") == "guest"]
    if not guest_low:
        return None
    return {
        "name": f"CONFIRMED guest SMB access enabled ({len(guest_low)} account)",
        "severity": "LOW", "cvss": "4.3",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": ("Guest / anonymous SMB access is enabled. Attackers can "
                     "enumerate visible shares + cached usernames without any "
                     "credentials. Verified by impacket second login. "
                     f"Fingerprint: {_fp_blurb(s)}."),
        "remediation": ("Disable the local guest account: "
                        "`net user guest /active:no`. Set GPO 'Accounts: Guest "
                        "account status' = Disabled. For Samba: ensure 'map to "
                        "guest = Never' and 'restrict anonymous = 2'. Remove "
                        "any null-session allowances."),
    }


def rule_suspected(s):
    g = _findings_by_severity(s)
    suspected = [f for f in g["LOW"] if f.get("confidence") == "SUSPECTED"]
    if not suspected:
        return None
    users = ", ".join(sorted({f.get("user", "?") for f in suspected}))[:200]
    return {
        "name": f"SUSPECTED SMB credential ({len(suspected)} - needs manual verification)",
        "severity": "LOW", "cvss": "3.7",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": ("Medusa reported these credentials as valid but the impacket "
                     "second-login verification could not confirm. Could be a "
                     "medusa false-positive OR an account with login-but-no-shell "
                     "OR network jitter during verify. "
                     f"Users: {users}."),
        "remediation": ("Manually verify with `smbclient -L //<host> -U <user>` "
                        "or impacket-smbclient. If auth DOES work, treat as "
                        "CONFIRMED MEDIUM/CRITICAL per privilege. If auth fails "
                        "manually, this was a false positive - safe to ignore "
                        "but file an issue for VulnusLab to tune medusa parsing."),
    }


def rule_chain_handoff(s):
    chain_next = s.get("chain_next") or []
    if not chain_next:
        return None
    return {
        "name": "Cross-scanner chain handoff suggested",
        "severity": "INFO",
        "evidence": ("Confirmed SMB credentials enable downstream scanners: "
                     + ", ".join(chain_next)),
        "remediation": ("Re-run scan with chain_id propagation to automatically "
                        "follow up with: " + ", ".join(chain_next) + ". These "
                        "will inherit the captured credentials via the VL-METHOD "
                        "chaining engine and pursue AD enumeration / persistence "
                        "/ lateral movement artifacts."),
        "cwe": "CWE-1006",
    }


MEDUSA_SMB_SPRAY_FINDING_RULES = [
    rule_unreachable,
    rule_input_missing,
    rule_positive_quick,
    rule_inconclusive,
    rule_lockout_hit,
    rule_signing_not_required,
    rule_confirmed_admin,
    rule_confirmed_user,
    rule_confirmed_guest,
    rule_suspected,
    rule_chain_handoff,
]
