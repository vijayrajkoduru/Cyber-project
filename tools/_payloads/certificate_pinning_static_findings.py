"""certificate_pinning_static — findings rules."""


def rule_positive_emit(s):
    pin = s.get("pinning_markers_found") or []
    insec = s.get("insecure_tls_markers") or []
    if pin and not insec:
        return {"name": f"Certificate pinning detected ({len(pin)} library marker(s))",
                "severity": "POSITIVE",
                "cwe": "CWE-295", "owasp": "M5:2023",
                "evidence": ", ".join(p["desc"] for p in pin[:5]),
                "remediation": "Good. Periodically rotate pinned certs (annual?) to "
                               "avoid breakage. Have a backup pin in case primary expires."}
    return None


def rule_no_pinning_no_insecure(s):
    pin = s.get("pinning_markers_found") or []
    insec = s.get("insecure_tls_markers") or []
    if pin or insec: return None
    return {"name": "No certificate pinning detected (and no insecure-TLS markers)",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-295", "owasp": "M5:2023",
            "evidence": f"scanned {s.get('files_scanned', 0)} files, no pinning + no bypass markers",
            "remediation": "App uses system trust store — vulnerable to MitM via "
                           "user-installed CAs (Burp on rooted device) and per-network "
                           "Trust-by-default issues. For sensitive apps (banking, "
                           "health) add OkHttp CertificatePinner or use Network Security "
                           "Config <pin-set>. Apple ATS recommends pinning via "
                           "URLSessionDelegate + SecTrustEvaluateWithError."}


def rule_insecure_tls(s):
    insec = s.get("insecure_tls_markers") or []
    if not insec: return None
    return {"name": f"INSECURE TLS detected ({len(insec)} marker(s)) — likely MitM-vulnerable",
            "severity": "CRITICAL", "cvss": "9.1",
            "cwe": "CWE-295", "owasp": "M5:2023",
            "evidence": " | ".join(i["desc"] for i in insec[:5]),
            "remediation": "Empty checkServerTrusted / Noop hostname verifiers / "
                           "trustAllSSL helpers DISABLE TLS validation entirely. "
                           "ALL traffic readable by anyone on the network. "
                           "Remove these. If you need staging/dev bypass: use a "
                           "Network Security Config debug-overrides block, not "
                           "production-shipped code paths."}
