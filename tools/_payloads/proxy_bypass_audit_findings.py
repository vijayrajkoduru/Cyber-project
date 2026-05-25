"""proxy_bypass_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("proxy_bypass_audit_total"):
        return None
    return {"name": "No proxy-detection or proxy-bypass code patterns",
            "severity": "POSITIVE",
            "evidence": f"{s.get('files_scanned', 0)} smali files scanned",
            "remediation": "Default Burp / mitmproxy MITM workflow will work. No additional pentest tooling needed for proxy interception.",
            "cwe": "CWE-693", "owasp": "M3:2023"}


def rule_proxy_defenses(s):
    defenses = s.get("proxy_defenses") or {}
    if not defenses:
        return None
    explicit_block = any(k in defenses for k in ("Proxy.NO_PROXY OkHttp config",
                                                   "ProxySelector setDefault",
                                                   "OkHttp .proxy() explicit"))
    sev = "MEDIUM" if explicit_block else "INFO"
    return {"name": f"{len(defenses)} proxy-defense pattern(s) - traffic interception may fail",
            "severity": sev, "cvss": "4.5" if sev == "MEDIUM" else None,
            "cwe": "CWE-693", "owasp": "M3:2023",
            "evidence": "; ".join(f"{k}: {len(v)} file(s)" for k, v in list(defenses.items())[:5]),
            "remediation": "Use Frida to hook the proxy-detection method, OR install a transparent proxy on the gateway (e.g. mitmproxy --mode transparent + iptables). Note which class to hook based on the evidence above."}


PROXY_BYPASS_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_proxy_defenses,
]
