"""push_messaging_secret_audit — findings rules."""


def rule_positive_emit(s):
    n = s.get("push_messaging_secret_audit_total", 0)
    if n > 0: return None
    return {"name": "No leaked push / messaging / cloud secrets detected",
            "severity": "POSITIVE",
            "cwe": "CWE-798", "owasp": "M9:2023",
            "evidence": f"scanned {s.get('files_scanned', 0)} files, 0 high-confidence secret patterns",
            "remediation": "Continue using gitleaks/trufflehog in CI to prevent regressions."}


def rule_critical_leak(s):
    crit = s.get("critical_count", 0)
    if crit == 0: return None
    crits = [h for h in (s.get("secret_hits") or []) if h["severity"] == "CRITICAL"]
    p8s = s.get("apns_p8_keys") or []
    return {"name": f"CRITICAL secret leak(s) in bundle ({crit})",
            "severity": "CRITICAL", "cvss": "9.8",
            "cwe": "CWE-798", "owasp": "M9:2023",
            "evidence": " | ".join(
                f"{h['type']}: {h['value']} in {h['file']}" for h in crits[:5]
            ) + (f" | APNs .p8: {', '.join(p8s[:3])}" if p8s else ""),
            "remediation": "EACH leaked secret must be ROTATED IMMEDIATELY at the "
                           "issuing provider (FCM console / Stripe / AWS / GitHub / Slack). "
                           "Anyone who extracts the APK NOW has these forever. After "
                           "rotation: rebuild the APK without the secret (move to "
                           "remote-config / Firebase Remote Config / Functions), audit "
                           "for misuse during exposure window."}


def rule_high_severity_leak(s):
    hits = s.get("secret_hits") or []
    high = [h for h in hits if h["severity"] == "HIGH"]
    if not high: return None
    return {"name": f"HIGH-severity secret leak(s) ({len(high)})",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-798", "owasp": "M9:2023",
            "evidence": " | ".join(
                f"{h['type']}: {h['value']} in {h['file']}" for h in high[:5]
            ),
            "remediation": "Rotate. These leak categories (Twilio SID, PayPal client) "
                           "enable account-level abuse but not full takeover. Move to "
                           "server-side proxy."}


def rule_ambiguous_api_key(s):
    hits = s.get("secret_hits") or []
    google = [h for h in hits if "Google API key" in h["type"]]
    if not google: return None
    return {"name": f"Google API key(s) bundled ({len(google)}) — may be FCM client or Maps",
            "severity": "INFO",
            "cwe": "CWE-200", "owasp": "M2:2023",
            "evidence": " | ".join(f"{h['value']} in {h['file']}" for h in google[:5]),
            "remediation": "AIza... keys can be FCM CLIENT (safe to bundle) OR Maps "
                           "JavaScript API (also safe with HTTP referer restriction) OR "
                           "server-side keys (NOT safe). Restrict each in Google Cloud "
                           "Console → Credentials → API restrictions (limit to expected "
                           "API + application restrictions limit to Android package name)."}
