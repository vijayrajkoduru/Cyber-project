"""proguard_obfuscation_audit — findings rules."""


def rule_positive_emit(s):
    ratio = s.get("short_name_ratio_pct", -1)
    own = s.get("own_classes", 0)
    if own == 0:
        return {"name": "No own classes detected (Kotlin-Multiplatform / Flutter app?)",
                "severity": "INFO", "cwe": "CWE-200", "owasp": "M9:2023",
                "evidence": "0 first-party classes detected in DEX",
                "remediation": "If this is a Flutter / RN / KMP app, native Dart/JS "
                               "bundles are scanned via flutter_rn_bundle_audit."}
    if ratio >= 70:
        return {"name": f"Code obfuscation detected ({ratio}% short class names)",
                "severity": "POSITIVE", "cwe": "CWE-693", "owasp": "M9:2023",
                "evidence": f"{s.get('short_names',0)}/{own} own classes have <=2 char names",
                "remediation": "Good. Continue using R8/ProGuard. For sensitive code paths "
                               "(payment, license-check), add DexGuard or commercial obfuscator "
                               "with control-flow obfuscation + string encryption."}
    return None


def rule_no_obfuscation(s):
    ratio = s.get("short_name_ratio_pct", -1)
    own = s.get("own_classes", 0)
    if own == 0 or ratio >= 30: return None
    sev = "MEDIUM" if ratio < 10 else "LOW"
    cvss = "5.3" if ratio < 10 else "3.5"
    sample = s.get("sample_long_names", [])[:5]
    return {"name": f"No code obfuscation ({ratio}% short names, {s.get('long_names',0)} verbose)",
            "severity": sev, "cvss": cvss,
            "cwe": "CWE-693", "owasp": "M9:2023",
            "evidence": "sample own classes: " + ", ".join(sample),
            "remediation": "Enable R8 minify in release build (minifyEnabled true + "
                           "proguard-rules.pro). Default ProGuard rules cover most "
                           "AndroidX/Kotlin compatibility. Class names alone won't "
                           "stop a determined attacker but raise the bar for casual "
                           "reverse engineering by 10x."}


def rule_partial_obfuscation(s):
    ratio = s.get("short_name_ratio_pct", -1)
    if not (30 <= ratio < 70): return None
    return {"name": f"Partial obfuscation: {ratio}% short class names",
            "severity": "LOW",
            "cwe": "CWE-693", "owasp": "M9:2023",
            "evidence": f"{s.get('short_names',0)}/{s.get('own_classes',0)} own classes obfuscated",
            "remediation": "Some classes are obfuscated, others aren't — likely due to "
                           "@Keep annotations or proguard-rules.pro keep-statements. "
                           "Audit which classes are exempted and confirm exemptions are "
                           "necessary (reflection, serialization)."}
