"""ad_ldap_signing_check - findings rules (LDAP relay surface, playbook §2 #23).

ZERO-FALSE-POSITIVE contract:
  - We can OBSERVE remotely, without creds: whether port 389 (cleartext LDAP)
    is open and whether LDAPS (636) is available. Those are facts.
  - We CANNOT fully confirm "LDAP signing not required" / "channel binding
    disabled" without an authenticated unsigned bind (that needs valid creds).
    Therefore the signing/CBT *enforcement* finding is INFO advisory, never a
    graded false positive.
  - A graded (LOW) finding fires ONLY for a real observed fact: cleartext LDAP
    (389) reachable while LDAPS (636) is NOT — a concrete downgrade surface.
"""


def rule_positive(s):
    if s.get("ad_ldap_signing_error"):
        return None
    if not s.get("ad_ldap_probed"):
        return None
    # Clean: LDAPS available (so a signed/encrypted channel exists).
    if s.get("ad_ldaps_available") and not s.get("ad_ldap_cleartext_only"):
        return {"name": "LDAPS (TLS) available on Domain Controller",
                "severity": "POSITIVE",
                "evidence": "Port 636 (LDAPS) reachable — encrypted LDAP channel available.",
                "remediation": "Enforce LDAP signing + channel binding and prefer LDAPS for clients.",
                "cwe": "CWE-319", "owasp": "A02:2021"}
    return None


def rule_cleartext_only(s):
    # Graded (LOW) ONLY when we actually observed 389 open but 636 closed.
    if not s.get("ad_ldap_cleartext_only"):
        return None
    return {"name": "Cleartext LDAP (389) reachable, LDAPS (636) not available",
            "severity": "LOW", "cvss": "3.7",
            "cwe": "CWE-319", "owasp": "A02:2021",
            "evidence": ("Port 389 answered an LDAP bind while port 636 (LDAPS) did not "
                         "respond — clients have no encrypted LDAP option, easing "
                         "LDAP credential interception and NTLM-relay-to-LDAP downgrade."),
            "remediation": ("Enable LDAPS on the DC (install a server-auth certificate from "
                            "your enterprise CA), then enforce LDAP signing "
                            "('Domain controller: LDAP server signing requirements' = "
                            "'Require signing') and LDAP channel binding "
                            "('Domain controller: LDAP server channel binding token "
                            "requirements' = 'Always'). This blocks ntlmrelayx -> LDAP.")}


def rule_signing_advisory(s):
    # Signing/CBT *enforcement* cannot be remotely confirmed without an
    # authenticated unsigned bind -> always INFO advisory.
    if s.get("ad_ldap_signing_error"):
        return None
    if not s.get("ad_ldap_probed"):
        return None
    return {"name": "LDAP signing / channel-binding enforcement (requires credentialed check)",
            "severity": "INFO",
            "evidence": (f"Observed: 389 open={s.get('ad_ldap_389_open')}, "
                         f"636 (LDAPS) open={s.get('ad_ldaps_available')}. "
                         f"Anonymous bind result: {s.get('ad_ldap_anon_result', 'n/a')}."),
            "remediation": ("[ADVISORY-BY-DESIGN] Whether the DC REQUIRES LDAP signing and "
                            "channel binding can only be proven with a valid low-priv account "
                            "(attempt an unsigned simple bind and observe rejection). Confirm "
                            "via: nxc ldap <dc> -u user -p pass -M ldap-checker, or the DC's "
                            "Directory Service event 2889 audit. Microsoft enforces signing by "
                            "default on patched DCs, but many environments relax it."),
            "cwe": "CWE-345", "owasp": "A02:2021"}


AD_LDAP_SIGNING_CHECK_FINDING_RULES = [rule_positive, rule_cleartext_only, rule_signing_advisory]
