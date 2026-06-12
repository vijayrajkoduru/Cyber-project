"""ad_asrep_roast - findings rules (AS-REP roasting, playbook §3 #36).

ZERO-FALSE-POSITIVE contract:
  - HIGH is emitted ONLY for accounts where the KDC actually returned an AS-REP
    (encrypted TGT) to a pre-auth-less AS-REQ. That response PROVES the account
    has DONT_REQ_PREAUTH set (UF_DONT_REQUIRE_PREAUTH) and is roastable. This is
    a detected condition on the live target, not a planned severity.
  - We do NOT crack the returned hash (VA-not-PT). We only record that the
    account is roastable.
  - When no userlist is supplied, the scanner emits an INFO advisory (input
    required) — never a graded finding.
"""


def rule_binary_missing(s):
    if s.get("ad_asrep_error") != "impacket not installed":
        return None
    return {"name": "AS-REP roast probe skipped - impacket not installed",
            "severity": "INFO",
            "evidence": "impacket Kerberos modules unavailable in scan image",
            "remediation": "Install impacket in the scan image (pip install impacket).",
            "cwe": "CWE-1006"}


def rule_input_missing(s):
    if not s.get("ad_asrep_input_missing"):
        return None
    return {"name": "AS-REP roast skipped - username input required",
            "severity": "INFO",
            "evidence": "options.userlist + options.domain were not provided",
            "remediation": ("Provide options.domain (AD FQDN) + options.userlist "
                            "(newline-separated sAMAccountNames, max 200). The probe sends a "
                            "pre-auth-less Kerberos AS-REQ per user and flags any account that "
                            "the KDC answers with a TGT (DONT_REQ_PREAUTH set). Detection only "
                            "- no hash cracking is performed."),
            "cwe": "CWE-1006"}


def rule_positive(s):
    if s.get("ad_asrep_error") or s.get("ad_asrep_input_missing"):
        return None
    tested = s.get("ad_asrep_users_tested", 0)
    if tested == 0:
        return None
    if s.get("ad_asrep_roastable"):
        return None
    return {"name": f"No AS-REP roastable accounts among {tested} tested",
            "severity": "POSITIVE",
            "evidence": f"{tested} account(s) tested; KDC required pre-auth for all.",
            "remediation": "Continue requiring Kerberos pre-authentication on all accounts.",
            "cwe": "CWE-294", "owasp": "A07:2021"}


def rule_roastable_accounts(s):
    roastable = s.get("ad_asrep_roastable") or []
    if not roastable:
        return None
    sample = ", ".join(str(u) for u in roastable[:8])
    return {"name": f"AS-REP roastable accounts detected ({len(roastable)})",
            "severity": "HIGH", "cvss": "8.1",
            "cwe": "CWE-294", "owasp": "A07:2021",
            "evidence": (f"KDC returned a TGT without pre-auth (DONT_REQ_PREAUTH set) for: "
                         f"{sample}. An attacker can request these AS-REPs offline and crack "
                         f"the account passwords (hashcat -m 18200) with NO valid credentials."),
            "remediation": ("Remove 'Do not require Kerberos preauthentication' "
                            "(UF_DONT_REQUIRE_PREAUTH) from every listed account in ADUC > "
                            "Account options. If pre-auth must stay disabled for a legacy app, "
                            "give that account a 25+ char random password and a fine-grained "
                            "password policy. Monitor event 4768 with pre-auth type 0.")}


AD_ASREP_ROAST_FINDING_RULES = [rule_binary_missing, rule_input_missing,
                                rule_positive, rule_roastable_accounts]
