"""emulator_detection_static — findings rules."""


def rule_positive_emit(s):
    n = s.get("emulator_detection_static_total", 0)
    if n > 0: return None
    return {"name": "Emulator detection markers NOT present in bundle",
            "severity": "LOW",
            "cwe": "CWE-693", "owasp": "M9:2023",
            "evidence": f"scanned {s.get('files_scanned', 0)} files, 0 emulator markers",
            "remediation": "For apps targeted by automated fraud (banking, social, "
                           "marketplaces with promo codes), add emulator detection — "
                           "Build.HARDWARE / FINGERPRINT checks + sensor presence + "
                           "qemu file checks. Combine with Play Integrity API server-side."}


def rule_emulator_detection_present(s):
    n = s.get("emulator_detection_static_total", 0)
    if n == 0: return None
    sample = s.get("emulator_markers_found", [])[:8]
    return {"name": f"Emulator detection present ({n} marker(s))",
            "severity": "POSITIVE",
            "cwe": "CWE-693", "owasp": "M9:2023",
            "evidence": ", ".join(sample),
            "remediation": "Good. Combine with Play Integrity API basicIntegrity + "
                           "ctsProfileMatch verdicts server-side for defense in depth. "
                           "Note: emulator detection alone is bypassable — used to "
                           "raise the cost of automated fraud, not stop targeted attacks."}
