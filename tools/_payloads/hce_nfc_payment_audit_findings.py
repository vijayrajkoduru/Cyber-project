"""hce_nfc_payment_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("hce_nfc_payment_audit_total", 0) > 0: return None
    return {"name": "No NFC / HCE payment surface", "severity": "POSITIVE",
            "cwe": "CWE-200", "owasp": "M9:2023",
            "evidence": "no NFC perm + no BIND_NFC_SERVICE",
            "remediation": "No NFC payment surface."}


def rule_hce_present(s):
    svcs = s.get("hce_services") or []
    if not svcs: return None
    return {"name": f"HCE payment service declared ({len(svcs)})",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-668", "owasp": "M9:2023",
            "evidence": " | ".join(s_["name"] for s_ in svcs),
            "remediation": "HCE apps emulate payment cards. Verify: (1) "
                           "aid-filter limits accepted AIDs to your payment "
                           "scheme, (2) NFC + READ_PHONE_STATE NOT combined "
                           "(IMSI deanonymization), (3) sensitive APDUs not "
                           "logged. PCI-DSS contactless requirements apply."}
