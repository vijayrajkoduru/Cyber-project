"""ncrack_rdp_spray - finding rules (VL-METHOD aware).

REWRITTEN 2026-06-05 for the VL-METHOD methodology pattern. Reads new
state keys populated by NcrackRdpSpray's 7-stage flow:
  - methodology_findings  : list of verified credentials
  - port_reachable        : bool from pre_flight
  - fingerprint           : dict {nla_enabled, cert_cn, rdp_version, ...}
  - nla_enabled           : bool short-cut for fingerprint.nla_enabled
  - chain_next            : list of follow-up scanner names

Severity now derives from CONFIRMED+privilege_level combination:
  CONFIRMED admin     -> CRITICAL  CVSS 9.8  (full Windows compromise)
  CONFIRMED user      -> MEDIUM    CVSS 6.5  (foothold, needs privesc)
  CONFIRMED guest     -> LOW       CVSS 4.3
  SUSPECTED any       -> LOW       CVSS 3.7  (manual confirm needed)
"""


def rule_unreachable(s):
    if s.get("port_reachable") is not False:
        return None
    return {
        "name": "RDP port unreachable - cannot test password security",
        "severity": "INFO",
        "evidence": s.get("skipped_reason") or "Port 3389 closed or filtered",
        "remediation": ("If RDP is meant to be exposed (e.g. RDS Gateway), verify "
                        "firewall + Terminal Services is running. If RDP is "
                        "intentionally blocked at the perimeter, this is good "
                        "hardening. Re-run scan once RDP is reachable to actually "
                        "test credential strength."),
        "cwe": "CWE-1006",
    }


def rule_binary_missing(s):
    if not s.get("ncrack_missing"):
        return None
    return {
        "name": "Ncrack binary not installed on scanner host",
        "severity": "INFO",
        "evidence": "shutil.which('ncrack') returned None on the backend container.",
        "remediation": ("Install ncrack inside the backend Dockerfile: "
                        "apt-get install -y ncrack. Quick-probe and deep-spray "
                        "stages cannot run without it."),
        "cwe": "CWE-1006",
    }


def rule_nla_disabled(s):
    # Separate INFO finding when the host fingerprints as RDP-without-NLA.
    # Only emit when port was reachable + fingerprint succeeded.
    if s.get("port_reachable") is not True:
        return None
    fp = s.get("fingerprint") or {}
    if not fp:
        return None
    # Only fire when we actually parsed a response AND NLA is NOT enabled.
    if not fp.get("raw_response_hex"):
        return None
    if fp.get("nla_enabled"):
        return None
    return {
        "name": "RDP server allows connections WITHOUT Network Level Authentication (NLA)",
        "severity": "INFO",
        "evidence": (f"Negotiated protocol: {fp.get('rdp_version', 'RDP standard')}. "
                     "NLA forces credential authentication BEFORE allocating a "
                     "session/desktop - without it, every connection burns RDP "
                     "session resources and exposes the login screen to fingerprint "
                     "/ exploit (BlueKeep CVE-2019-0708 class)."),
        "remediation": ("Enable NLA on the host: Group Policy -> Computer "
                        "Configuration -> Admin Templates -> Windows Components -> "
                        "Remote Desktop Services -> Remote Desktop Session Host -> "
                        "Security -> Require user authentication for remote "
                        "connections by using Network Level Authentication = Enabled. "
                        "Or via reg: HKLM\\System\\CurrentControlSet\\Control\\"
                        "Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication=1."),
        "cwe": "CWE-287",
        "owasp": "A07:2021",
    }


def rule_input_missing(s):
    # Only fires when pre_flight succeeded but customer didn't provide
    # userlist/passlist for the deep_scan stage. Quick-probe still ran
    # against 5 known defaults regardless of customer input.
    deep_skipped = s.get("deep_skipped") or ""
    if "userlist/passlist not supplied" not in deep_skipped:
        return None
    hits = s.get("methodology_total", 0)
    if hits > 0:
        # If quick-probe already found something, don't dilute with INFO
        return None
    return {
        "name": "Deep spray skipped - userlist/passlist not provided",
        "severity": "INFO",
        "evidence": ("Quick-probe ran 5 known-bad RDP defaults (Administrator/blank, "
                     "admin/admin, guest/blank, user/user, test/test) - none worked. "
                     "To run a full spray, provide options.userlist + options.passlist "
                     "on the request body (newline-separated). Max 10 users x 25 pwds."),
        "remediation": ("Supply options.userlist + options.passlist to test your "
                        "organization's Windows password policy. Recommended seed: "
                        "top-5 admin usernames (Administrator, admin, svc_, helpdesk, "
                        "sqladmin) + breach corpus top-20 passwords + your company "
                        "name variants."),
        "cwe": "CWE-1006",
    }


def rule_positive_quick(s):
    # Quick-probe ran, no hits, no real findings - GOOD signal
    if s.get("methodology_total", 0) > 0:
        return None
    if s.get("port_reachable") is not True:
        return None
    if s.get("quick_probe_attempts", 0) == 0:
        return None
    fp = s.get("fingerprint") or {}
    return {
        "name": "RDP rejects all 5 known-bad default credentials",
        "severity": "POSITIVE",
        "evidence": (f"Tried {s.get('quick_probe_attempts', 5)} known-bad RDP defaults "
                     f"(Administrator/blank, admin/admin, guest/blank, user/user, "
                     f"test/test); all rejected. RDP protocol: "
                     f"{fp.get('rdp_version', 'unknown')}. "
                     f"NLA: {'enabled' if fp.get('nla_enabled') else 'disabled'}."),
        "remediation": ("Continue rejecting default credentials. If NLA is disabled, "
                        "enable it (see separate INFO finding). Consider moving RDP "
                        "behind RDS Gateway or VPN, and enforcing MFA via Duo or "
                        "Microsoft Authenticator for all RDP sessions."),
        "cwe": "CWE-521",
        "owasp": "A07:2021",
    }


def _findings_by_severity(s):
    """Return methodology_findings grouped by severity (computed from
    confidence + privilege_level)."""
    out = {"CRITICAL": [], "MEDIUM": [], "LOW_GUEST": [], "LOW_SUSPECT": []}
    for f in (s.get("methodology_findings") or []):
        conf = f.get("confidence", "SUSPECTED")
        priv = f.get("privilege_level", "unknown")
        if conf == "CONFIRMED":
            if priv == "admin":
                out["CRITICAL"].append(f)
            elif priv == "guest":
                out["LOW_GUEST"].append(f)
            else:
                out["MEDIUM"].append(f)
        else:
            out["LOW_SUSPECT"].append(f)
    return out


def rule_confirmed_admin(s):
    g = _findings_by_severity(s)
    if not g["CRITICAL"]:
        return None
    users = ", ".join(f.get("user", "?") for f in g["CRITICAL"][:5])
    return {
        "name": f"CONFIRMED administrator RDP access via password ({len(g['CRITICAL'])} account)",
        "severity": "CRITICAL", "cvss": "9.8",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": ("Administrator account(s) on the Windows host compromised via "
                     "password spray. Verified by a separate ncrack subprocess "
                     "(verification_method=ncrack_second_attempt). Privilege "
                     "classified as 'admin' via WinRM whoami/priv (SeDebug/"
                     "SeImpersonate or BUILTIN\\Administrators group) or username "
                     "heuristic. Compromised users: " + users + ". "
                     "Full Windows host compromise + lateral-pivot launcher. "
                     "(Passwords redacted per VulnusLab privacy policy.)"),
        "remediation": ("CRITICAL - rotate the compromised account password(s) "
                        "immediately and audit Windows Security log (Event ID 4624 "
                        "Type 10) for prior unauthorized RDP logons. "
                        "1. Enforce 14-char+ passphrases via GPO + Account Lockout "
                        "(5 fails -> 15 min). "
                        "2. Pull RDP off public interfaces - put it behind RDS "
                        "Gateway, VPN or ZTNA tunnel. "
                        "3. Enable NLA + MFA (Duo / Microsoft Authenticator). "
                        "4. Restrict RDP source IPs via Windows Firewall to admin "
                        "jump boxes only. "
                        "5. Treat host as compromised until forensic review clears it."),
    }


def rule_confirmed_user(s):
    g = _findings_by_severity(s)
    if not g["MEDIUM"]:
        return None
    users = ", ".join(f.get("user", "?") for f in g["MEDIUM"][:5])
    return {
        "name": f"CONFIRMED regular user RDP access via password ({len(g['MEDIUM'])} account)",
        "severity": "MEDIUM", "cvss": "6.5",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": ("Non-admin Windows user account(s) compromised via RDP password "
                     "spray. Verified by a separate ncrack subprocess. Local privesc "
                     "(unquoted service paths, SeImpersonatePrivilege abuse, "
                     "PrintNightmare-class) required to reach SYSTEM, but the "
                     "attacker now has interactive desktop, can drop tools, harvest "
                     "browser credentials, and pivot. Compromised users: " + users + "."),
        "remediation": ("Force password reset on the affected accounts and notify "
                        "the owner(s). Enable password complexity GPO + Account "
                        "Lockout. Restrict RDP access via 'Remote Desktop Users' "
                        "group hygiene - remove users who don't need remote login. "
                        "Enable NLA + MFA. Consider AppLocker / WDAC to limit what "
                        "the attacker can execute post-login."),
    }


def rule_confirmed_guest(s):
    g = _findings_by_severity(s)
    if not g["LOW_GUEST"]:
        return None
    users = ", ".join(f.get("user", "?") for f in g["LOW_GUEST"][:5])
    return {
        "name": f"CONFIRMED guest RDP access via password ({len(g['LOW_GUEST'])} account)",
        "severity": "LOW", "cvss": "4.3",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": ("Guest account RDP login confirmed. Guest privileges are very "
                     "limited but the foothold can be used for reconnaissance, "
                     "kerberoasting, or chaining with local privesc. "
                     "Compromised users: " + users + "."),
        "remediation": ("Disable the built-in Guest account (it should be disabled "
                        "by default on Windows 10/11/Server 2019+): "
                        "net user Guest /active:no. Audit the host for who re-"
                        "enabled it and why."),
    }


def rule_suspected(s):
    g = _findings_by_severity(s)
    if not g["LOW_SUSPECT"]:
        return None
    return {
        "name": f"SUSPECTED RDP credential ({len(g['LOW_SUSPECT'])} - needs manual verification)",
        "severity": "LOW", "cvss": "3.7",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": ("Ncrack reported these credentials as valid on first attempt "
                     "but the second-attempt verification did NOT reproduce the "
                     "success. Could be ncrack false-positive, an intermittent "
                     "NLA negotiation timeout, or an account flagged for lockout "
                     "mid-scan. Users: " +
                     ", ".join(f.get("user", "?") for f in g["LOW_SUSPECT"][:5])),
        "remediation": ("Manually verify each user/password pair with a real RDP "
                        "client (mstsc, xfreerdp, Remmina). If login succeeds, "
                        "treat as CRITICAL/MEDIUM/LOW per the privilege level. "
                        "If it consistently fails, the original ncrack report was "
                        "a false-positive and no action is required."),
    }


def rule_chain_handoff(s):
    chain_next = s.get("chain_next") or []
    if not chain_next:
        return None
    return {
        "name": "Cross-scanner chain handoff suggested",
        "severity": "INFO",
        "evidence": ("Confirmed RDP credentials enable downstream Windows post-"
                     "exploitation scanners: " + ", ".join(chain_next)),
        "remediation": ("Re-run scan with chain_id propagation to automatically "
                        "follow up with: " + ", ".join(chain_next) + ". "
                        "These will inherit the captured creds via the VL-METHOD "
                        "chaining engine and check for persistence artefacts, "
                        "WinPEAS privesc paths, and lateral-pivot pre-positioning."),
        "cwe": "CWE-1006",
    }


NCRACK_RDP_SPRAY_FINDING_RULES = [
    rule_unreachable,
    rule_binary_missing,
    rule_nla_disabled,
    rule_input_missing,
    rule_positive_quick,
    rule_confirmed_admin,
    rule_confirmed_user,
    rule_confirmed_guest,
    rule_suspected,
    rule_chain_handoff,
]
