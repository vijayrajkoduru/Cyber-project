"""ad_smb_os_fingerprint - findings rules.

ZERO-FALSE-POSITIVE contract:
  - Graded severity (HIGH) is emitted ONLY when the SMB negotiate actually
    returned an SMBv1 dialect from the live target.
  - OS build / dialect intel is always INFO (cannot confirm patch level
    remotely without exploitation -> advisory).
"""


def rule_positive(s):
    info = s.get("ad_smb_os_info") or {}
    if s.get("ad_smb_unreachable") or s.get("ad_smb_os_fingerprint_error"):
        return None
    if not info:
        return None
    if s.get("ad_smbv1_enabled"):
        return None  # not a clean bill of health; the SMBv1 rule fires instead
    return {"name": "SMB negotiation reached target (modern dialect only)",
            "severity": "POSITIVE",
            "evidence": (f"Negotiated dialect: {info.get('dialect', '?')}; "
                         f"server: {info.get('server_name', 'host')}; "
                         f"SMBv1 not offered."),
            "remediation": "Continue to keep SMBv1 disabled domain-wide.",
            "cwe": "CWE-477", "owasp": "A06:2021"}


def rule_smbv1_enabled(s):
    # HIGH only when SMBv1 was ACTUALLY negotiated on the live target.
    if not s.get("ad_smbv1_enabled"):
        return None
    info = s.get("ad_smb_os_info") or {}
    return {"name": "Legacy SMBv1 enabled on Domain Controller",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-477", "owasp": "A06:2021",
            "evidence": (f"Target accepted an SMBv1 (NT LM 0.12) negotiate. "
                         f"Server: {info.get('server_name', 'host')}; "
                         f"OS: {info.get('server_os', 'unknown')}."),
            "remediation": ("Disable SMBv1 on every DC + member server. PowerShell: "
                            "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol. "
                            "SMBv1 has no signing/encryption and is the EternalBlue (MS17-010) "
                            "attack surface; it also blocks enforcement of SMB signing.")}


def rule_os_build_intel(s):
    # Build/OS string is real intel but maps to CVE exposure only if unpatched,
    # which we cannot confirm remotely -> always INFO (advisory).
    info = s.get("ad_smb_os_info") or {}
    build = info.get("server_os") or ""
    if not build:
        return None
    return {"name": "SMB server OS / build fingerprinted",
            "severity": "INFO",
            "evidence": (f"OS banner: {build}; dialect: {info.get('dialect', '?')}; "
                         f"domain: {info.get('server_domain', '')}"),
            "remediation": ("[ADVISORY] OS build alone does not prove a missing patch. "
                            "Cross-reference the build number against the current monthly "
                            "cumulative update for the DC role. Patch-level confirmation "
                            "requires host or credentialed scanning."),
            "cwe": "CWE-200", "owasp": "A06:2021"}


AD_SMB_OS_FINGERPRINT_FINDING_RULES = [rule_positive, rule_smbv1_enabled, rule_os_build_intel]
