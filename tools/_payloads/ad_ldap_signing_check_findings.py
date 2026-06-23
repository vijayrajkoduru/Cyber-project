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
    # ZERO-FP: "389 open and 636 closed" is NOT proof that the DC fails to
    # require LDAP signing / channel binding. Signing and CBT are enforced on
    # the 389 connection itself (StartTLS / SASL sign+seal), independently of
    # whether LDAPS (636) is offered. Modern, patched AD enforces signing by
    # default, and 636 may simply be closed because no server-auth certificate
    # is installed - which does NOT make 389 a cleartext-credential channel.
    # Proving signing is not required needs an authenticated unsigned bind
    # (valid creds). Therefore this observation is emitted as an INFO advisory,
    # not a graded LOW false positive.
    if not s.get("ad_ldap_cleartext_only"):
        return None
    return {"name": "LDAPS (636) not reachable; LDAP signing enforcement requires a credentialed check (advisory)",
            "severity": "INFO",
            "cwe": "CWE-319", "owasp": "A02:2021",
            "evidence": ("Port 389 answered an LDAP bind while port 636 (LDAPS) did not "
                         "respond. NOTE: this does NOT prove credentials traverse the wire "
                         "in cleartext - LDAP signing and channel binding are enforced on the "
                         "389 connection (SASL sign+seal / StartTLS) independently of whether "
                         "LDAPS is offered, and patched DCs enforce signing by default. 636 "
                         "may simply be closed because no server-auth certificate is installed. "
                         "Whether the DC actually requires signing can only be confirmed with a "
                         "valid account (attempt an unsigned simple bind and observe rejection)."),
            "remediation": ("[ADVISORY - credentialed check needed] Confirm signing enforcement "
                            "via: nxc ldap <dc> -u user -p pass -M ldap-checker, or the DC's "
                            "Directory Service event 2889 audit. Recommended hardening regardless: "
                            "install a server-auth certificate to enable LDAPS (636), and ensure "
                            "'Domain controller: LDAP server signing requirements' = 'Require "
                            "signing' and 'LDAP server channel binding token requirements' = "
                            "'Always'. These block ntlmrelayx -> LDAP.")}


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
