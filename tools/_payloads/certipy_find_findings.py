"""certipy_find - findings rules."""


def rule_positive(s):
    if s.get("certipy_find_total"):
        return None
    if s.get("certipy_find_error"):
        return None
    if not (s.get("certipy_cas") or s.get("certipy_templates_count")):
        return None
    return {"name": "AD CS enumerated - no obviously vulnerable templates",
            "severity": "POSITIVE",
            "evidence": (f"Mode: {s.get('certipy_auth_mode', '?')}; "
                         f"CAs: {len(s.get('certipy_cas') or [])}; "
                         f"Templates: {s.get('certipy_templates_count', 0)}"),
            "remediation": ("Continue auditing templates quarterly. New templates added by IT teams "
                            "often re-introduce ESC1/ESC4 over time."),
            "cwe": "CWE-295", "owasp": "A02:2021"}


def rule_vulnerable_templates(s):
    vts = s.get("certipy_vulnerable_templates") or []
    if not vts:
        return None
    by_esc = {}
    for t in vts:
        for v in t.get("vulns", []):
            esc = str(v)
            by_esc.setdefault(esc, []).append(t["template"])
    summary = "; ".join(f"{esc}: {', '.join(tpls[:3])}" for esc, tpls in list(by_esc.items())[:6])
    return {"name": f"AD CS - {len(vts)} vulnerable certificate template(s) - DOMAIN ADMIN PATH",
            "severity": "CRITICAL", "cvss": "9.8",
            "cwe": "CWE-295", "owasp": "A02:2021",
            "evidence": f"Vulnerabilities found: {summary}",
            "remediation": ("Critical - any of these templates allow privilege escalation to Domain Admin: "
                            "ESC1 (enrollee supplies subject) -> Certipy req -upn administrator. "
                            "ESC4 (write template ACL) -> rewrite template config + ESC1. "
                            "ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2) -> any-template ESC1. "
                            "ESC8 (HTTP NTLM relay to /certsrv) -> coerce + relay + cert. "
                            "Fix: in CA mgmt console set Subject Name to 'Build from AD info' "
                            "(blocks ESC1), remove low-priv ACLs from templates (blocks ESC4), "
                            "set EDITF_ATTRIBUTESUBJECTALTNAME2=0 (blocks ESC6), disable HTTP enrollment "
                            "or enforce EPA (blocks ESC8). Audit with Certipy after every change.")}


def rule_ca_inventory_only(s):
    if not s.get("certipy_ca_inventory_only"):
        return None
    cas = s.get("certipy_cas") or []
    return {"name": f"{len(cas)} AD CS Certificate Authorities discovered",
            "severity": "INFO",
            "evidence": "CAs: " + ", ".join(c.get("cn", "?") if isinstance(c, dict) else str(c) for c in cas[:5]),
            "remediation": ("Anonymous mode could only enum CAs, not templates. Re-run with domain "
                            "credentials (set options.domain/username/password) for full ESC1-ESC15 audit."),
            "cwe": "CWE-200"}


CERTIPY_FIND_FINDING_RULES = [rule_positive, rule_vulnerable_templates, rule_ca_inventory_only]
