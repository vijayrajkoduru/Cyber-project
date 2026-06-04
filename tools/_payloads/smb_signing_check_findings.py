"""smb_signing_check - findings rules."""


def rule_positive(s):
    if s.get("smb_unreachable") or s.get("smb_signing_check_error"):
        return None
    info = s.get("smb_server_info") or {}
    if info.get("signing_required") is not True:
        return None
    return {"name": "SMB signing required on target",
            "severity": "POSITIVE",
            "evidence": f"signing_required=True on {info.get('server_name', 'host')}",
            "remediation": "Keep enforcing SMB signing — blocks NTLM relay attacks.",
            "cwe": "CWE-345", "owasp": "A02:2021"}


def rule_signing_not_required(s):
    f = s.get("smb_signing_findings") or []
    if not any(x.get("check") == "smb_signing_not_required" for x in f):
        return None
    info = s.get("smb_server_info") or {}
    return {"name": "SMB signing NOT required - vulnerable to NTLM relay",
            "severity": "HIGH", "cvss": "8.1",
            "cwe": "CWE-345", "owasp": "A02:2021",
            "evidence": (f"SMB negotiate succeeded on {info.get('server_name', 'host')} "
                         f"with signing_required=False. "
                         f"OS: {info.get('server_os', 'unknown')}. "
                         f"Domain: {info.get('server_domain', '')}"),
            "remediation": ("Enable SMB signing on the Domain Controller via GPO: "
                            "Computer Configuration > Policies > Windows Settings > "
                            "Security Settings > Local Policies > Security Options > "
                            "'Microsoft network server: Digitally sign communications (always)' = Enabled. "
                            "Apply to Default Domain Controllers Policy. Without signing, attacker can "
                            "coerce DC (PetitPotam/DFSCoerce) and relay NTLM to AD CS for domain takeover.")}


SMB_SIGNING_CHECK_FINDING_RULES = [rule_positive, rule_signing_not_required]
