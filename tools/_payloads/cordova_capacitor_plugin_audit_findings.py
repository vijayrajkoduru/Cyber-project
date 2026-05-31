"""cordova_capacitor_plugin_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("is_cordova") or s.get("is_capacitor"): return None
    return {"name": "Not a Cordova/Capacitor hybrid app",
            "severity": "POSITIVE", "cwe": "CWE-1395", "owasp": "M9:2023",
            "evidence": "no cordova.js / capacitor.config detected",
            "remediation": "Pure-native app — no hybrid plugin surface."}


def rule_bad_plugins(s):
    bad = s.get("bad_plugins") or []
    if not bad: return None
    return {"name": f"Known-vulnerable Cordova/Capacitor plugin(s) ({len(bad)})",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-1395", "owasp": "M9:2023",
            "evidence": " | ".join(f"{b['plugin']}: {b['issue']}" for b in bad[:3]),
            "remediation": "Upgrade each flagged plugin to latest stable. For "
                           "deprecated Cordova plugins, migrate to Capacitor "
                           "equivalents (Capacitor has stricter URL validation, "
                           "better TypeScript support, faster security response)."}


def rule_plugin_inventory(s):
    plugins = s.get("plugins_found") or []
    if not plugins: return None
    if s.get("bad_plugins"): return None  # higher rule already fired
    return {"name": f"Hybrid app plugin inventory ({len(plugins)})",
            "severity": "INFO", "cwe": "CWE-1395",
            "evidence": ", ".join(plugins[:8])
                          + (f" + {len(plugins)-8} more" if len(plugins) > 8 else ""),
            "remediation": "Cross-reference each plugin against Snyk/OSV.dev. "
                           "Capacitor 5+ has automatic CVE checks via `npm audit`. "
                           "For Cordova: cordova-check-plugins."}
