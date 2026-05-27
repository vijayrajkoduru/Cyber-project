"""flutter_rn_bundle_audit — findings rules."""


def rule_positive_emit(s):
    if s.get("flutter_rn_bundle_audit_total"):
        return None
    return {"name": "Native (non-cross-platform) build — no JS bundle leakage surface",
            "severity": "POSITIVE",
            "evidence": "no Flutter / RN / Capacitor / Cordova fingerprint",
            "remediation": "Continue native build practices; this is the most RE-resistant option.",
            "cwe": "CWE-540", "owasp": "M7:2023"}


def rule_framework_fingerprint(s):
    fw = s.get("framework")
    if not fw or fw == "native":
        return None
    notes = {
        "flutter": "Flutter AOT — extract Dart classes with reFlutter (https://github.com/Impact-I/reFlutter).",
        "react_native": "React Native — index.android.bundle is plain JS, often contains live URLs, dev hostnames and tokens.",
        "capacitor": "Capacitor — web app + JS bridge; inspect public/ and plugins/.",
        "cordova": "Cordova — assets/www/ is the whole web app; full HTML/JS source is shipped.",
    }
    return {"name": f"Cross-platform framework detected: {fw}",
            "severity": "INFO",
            "cwe": "CWE-540", "owasp": "M7:2023",
            "evidence": s.get("framework_evidence") or "fingerprint matched",
            "remediation": notes.get(fw, "Cross-platform builds expose bundle source — consider obfuscation + bundle minification.")}


def rule_bundle_not_minified(s):
    if s.get("framework") != "react_native":
        return None
    if s.get("bundle_minified"):
        return None
    sz = s.get("bundle_size") or 0
    return {"name": "React Native bundle not minified (source readable)",
            "severity": "MEDIUM", "cvss": "4.3",
            "cwe": "CWE-540", "owasp": "M7:2023",
            "evidence": f"index.android.bundle: {sz:,} bytes, avg line length suggests unminified",
            "remediation": "Enable production mode (`react-native bundle --dev false --minify true`) and Hermes bytecode to defeat trivial source reading."}


def rule_bundle_secrets(s):
    secrets = s.get("bundle_secrets") or []
    if not secrets:
        return None
    return {"name": f"JS bundle leaks {len(secrets)} suspected secret(s)",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-798", "owasp": "M1:2023",
            "evidence": ", ".join(secrets[:8]),
            "remediation": "Never bundle live API keys, JWT tokens, or cloud creds into client-side JS. Move secrets server-side; for unavoidable client tokens use short-lived per-user tokens fetched at runtime."}


FLUTTER_RN_BUNDLE_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_framework_fingerprint,
    rule_bundle_not_minified,
    rule_bundle_secrets,
]
