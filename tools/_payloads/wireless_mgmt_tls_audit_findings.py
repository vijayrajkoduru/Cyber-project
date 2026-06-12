"""wireless_mgmt_tls_audit - findings rules.

ZERO-FALSE-POSITIVE discipline: every graded finding below corresponds to a
condition actively confirmed on the certificate / TLS handshake actually served
by the target (date math, issuer==subject + vendor-default string match, or a
deprecated protocol genuinely negotiated). No condition is inferred from a
precondition. Unreachable / clean TLS => INFO / POSITIVE only.
"""


def rule_no_target(s):
    if not s.get("no_target"):
        return None
    return {"name": "No target supplied to wireless management TLS audit",
            "severity": "INFO",
            "evidence": "ScanRequest.target was empty",
            "remediation": "Provide the hostname/IP of the wireless mgmt plane's HTTPS endpoint.",
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_resolve_failed(s):
    host = s.get("resolve_failed")
    if not host:
        return None
    return {"name": f"Target '{host}' did not resolve",
            "severity": "INFO",
            "evidence": f"socket.gethostbyname('{host}') failed",
            "remediation": ("Internal-only wireless controllers (RFC1918) are correctly "
                            "unreachable from external SaaS; audit them with an on-LAN agent."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_tls_unreachable(s):
    if not s.get("tls_unreachable"):
        return None
    ip = s.get("resolved_ip", "")
    return {"name": "No TLS endpoint reachable on the wireless management port",
            "severity": "POSITIVE",
            "evidence": (f"Resolved to {ip}; TLS handshake on the configured port did not "
                         f"complete ({s.get('tls_error', 'connect failed')})"),
            "remediation": ("If the management plane is intentionally not internet-exposed, "
                            "this is good posture. Keep AP/controller HTTPS admin behind "
                            "VPN/firewall."),
            "cwe": "CWE-1188", "owasp": "A05:2021"}


def rule_cert_expired(s):
    if not (s.get("cert_expired") or s.get("cert_not_yet_valid")):
        return None
    expired = s.get("cert_expired")
    when = "expired on " + str(s.get("cert_not_after")) if expired else \
           "not valid until " + str(s.get("cert_not_before"))
    return {"name": ("Wireless management TLS certificate is "
                     + ("expired" if expired else "not yet valid")),
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-298", "owasp": "A02:2021",
            "verified_exploit": True,  # confirmed by date math on the served cert
            "evidence": (f"The certificate served by {s.get('target_host','')}:"
                         f"{s.get('tls_port','')} (subject CN "
                         f"'{s.get('cert_subject_cn') or 'n/a'}') is {when}"),
            "remediation": ("Reissue and deploy a currently-valid certificate on the wireless "
                            "controller/AP admin interface. An invalid management cert trains "
                            "admins to click through TLS warnings, enabling MITM of admin "
                            "sessions. Automate renewal (ACME) where the platform supports it.")}


def rule_vendor_default_cert(s):
    if not s.get("cert_vendor_default"):
        return None
    return {"name": "Wireless management plane uses a default / vendor self-signed certificate",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-1392", "owasp": "A05:2021",
            "verified_exploit": True,  # issuer==subject + matched vendor default marker
            "evidence": (f"The HTTPS cert on {s.get('target_host','')}:{s.get('tls_port','')} "
                         f"is self-signed (issuer == subject) and matches a known AP/controller "
                         f"default-cert marker: issuer CN '{s.get('cert_issuer_cn') or 'n/a'}', "
                         f"subject CN '{s.get('cert_subject_cn') or 'n/a'}'"),
            "remediation": ("Replace the factory/default self-signed certificate with one from a "
                            "trusted internal or public CA, with a CN/SAN matching the management "
                            "hostname. Default vendor certs share private keys across every "
                            "device of that model and enable trivial MITM of the admin session.")}


def rule_deprecated_tls(s):
    if not s.get("tls_deprecated_protocol"):
        return None
    return {"name": "Wireless management plane negotiated a deprecated TLS protocol",
            "severity": "MEDIUM", "cvss": "5.9",
            "cwe": "CWE-326", "owasp": "A02:2021",
            "verified_exploit": True,  # protocol actually negotiated in the handshake
            "evidence": (f"{s.get('target_host','')}:{s.get('tls_port','')} negotiated "
                         f"{s.get('tls_protocol')} (cipher {s.get('tls_cipher') or 'n/a'}) — "
                         "a deprecated, attack-prone TLS version"),
            "remediation": ("Disable TLS 1.0/1.1 (and SSLv3) on the wireless controller/AP admin "
                            "service; require TLS 1.2+ with modern ciphers. Deprecated TLS on a "
                            "management plane is a PCI DSS 4.0 §4.2.1 / NIST SP 800-52 violation.")}


def rule_tls_clean(s):
    """No graded TLS issue confirmed but a cert WAS served — POSITIVE context."""
    if not s.get("tls_protocol"):
        return None
    if (s.get("cert_expired") or s.get("cert_not_yet_valid")
            or s.get("cert_vendor_default") or s.get("tls_deprecated_protocol")):
        return None
    return {"name": "Wireless management TLS endpoint served a valid, modern certificate",
            "severity": "POSITIVE",
            "evidence": (f"{s.get('target_host','')}:{s.get('tls_port','')} negotiated "
                         f"{s.get('tls_protocol')} with cert issued by "
                         f"'{s.get('cert_issuer_cn') or 'n/a'}', valid until "
                         f"{s.get('cert_not_after') or 'n/a'}"),
            "remediation": ("TLS posture on the exposed management plane is acceptable. Confirm "
                            "the interface still needs to be internet-reachable; prefer "
                            "VPN-only access regardless of TLS quality."),
            "cwe": "N/A", "owasp": "N/A"}


WIRELESS_MGMT_TLS_AUDIT_FINDING_RULES = [
    rule_no_target,
    rule_resolve_failed,
    rule_tls_unreachable,
    rule_cert_expired,
    rule_vendor_default_cert,
    rule_deprecated_tls,
    rule_tls_clean,
]
