"""deep_link_hijack_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("deep_link_hijack_audit_total"):
        return None
    return {"name": "Deep-link surface clean",
            "severity": "POSITIVE",
            "evidence": (f"Verified app-links={s.get('verified_app_links', 0)} "
                         f"unverified-custom={len(s.get('custom_scheme_unverified') or [])} "
                         f"unverified-http={len(s.get('http_link_unverified') or [])}"),
            "remediation": "Continue using autoVerify=true on HTTP/S app-links with assetlinks.json.",
            "cwe": "CWE-940", "owasp": "M4:2023"}


def rule_http_unverified(s):
    h = s.get("http_link_unverified") or []
    if not h: return None
    return {"name": f"HTTP/S deep-link without autoVerify in {len(h)} intent-filter(s)",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-940", "owasp": "M4:2023",
            "evidence": "Hosts: " + ", ".join(e["host"] for e in h[:6]),
            "remediation": ("Add android:autoVerify=\"true\" + serve /.well-known/assetlinks.json from the "
                            "host. Without verification a competing app can register the same host and "
                            "intercept OAuth redirects / password-reset links.")}


def rule_custom_scheme_unverified(s):
    c = s.get("custom_scheme_unverified") or []
    if not c: return None
    return {"name": f"Custom deep-link scheme registered by {len(c)} intent-filter(s)",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-940", "owasp": "M4:2023",
            "evidence": "Schemes: " + ", ".join(e["scheme"] for e in c[:6]),
            "remediation": ("Custom schemes can't be claimed. Switch to App Links (HTTPS + assetlinks.json) "
                            "for auth-bearing flows. Otherwise verify caller identity via UID + signature.")}


DEEP_LINK_HIJACK_AUDIT_FINDING_RULES = [rule_positive_emit, rule_http_unverified, rule_custom_scheme_unverified]
