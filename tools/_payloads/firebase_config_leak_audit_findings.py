"""firebase_config_leak_audit — findings rules."""


def rule_positive_emit(s):
    n = s.get("firebase_config_leak_audit_total", 0)
    if n > 0: return None
    return {"name": "No Firebase config files in app bundle",
            "severity": "POSITIVE",
            "cwe": "CWE-200", "owasp": "M2:2023",
            "evidence": "no google-services.json / GoogleService-Info.plist found",
            "remediation": "App doesn't use Firebase — no Firebase-specific risk surface."}


def rule_firebase_present(s):
    if s.get("firebase_config_leak_audit_total", 0) == 0: return None
    db_urls = s.get("firebase_db_urls") or []
    project_ids = s.get("project_ids") or []
    api_keys = s.get("api_keys") or []
    return {"name": f"Firebase config bundled — project_id={', '.join(project_ids[:2])}",
            "severity": "INFO",
            "cwe": "CWE-200", "owasp": "M2:2023",
            "evidence": (f"project_ids={project_ids[:3]} | "
                          f"api_keys={[k[:20]+'…' for k in api_keys[:2]]} | "
                          f"db_urls={db_urls[:2]}"),
            "remediation": "Firebase config files are MEANT to be bundled — these "
                           "fields aren't 'secrets'. BUT the security of the project "
                           "depends entirely on Firestore / Realtime DB / Storage "
                           "RULES. Test rules at:\n"
                           "  https://console.firebase.google.com/project/PROJECT_ID/database/rules\n"
                           "Default-permissive rules ('allow read, write: if true') "
                           "are the most common Firebase breach root cause."}


def rule_realtime_db_url(s):
    db_urls = s.get("firebase_db_urls") or []
    if not db_urls: return None
    return {"name": f"Firebase Realtime Database URL(s) bundled — TEST PUBLIC ACCESS",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-200", "owasp": "M2:2023",
            "evidence": " | ".join(db_urls[:3]),
            "remediation": ("For EACH URL, try:  curl '<DB_URL>/.json'  — if it "
                            "returns JSON instead of 401 Permission Denied, your DB "
                            "is publicly readable. Same for /USERS.json / /MESSAGES.json. "
                            "Lock down via Firebase Console → Realtime DB → Rules → "
                            "'.read': 'auth != null'.")}
