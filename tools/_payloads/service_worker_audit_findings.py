"""service_worker_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("service_worker_audit_total"):
        return None
    return {"name": "WebView Service Worker posture clean",
            "severity": "POSITIVE",
            "evidence": f"SW registers={len(s.get('sw_register_calls') or [])} | controller set={s.get('sw_controller_set')}",
            "remediation": "Continue setting WebView ServiceWorkerController explicitly to gate SW behaviour.",
            "cwe": "CWE-668", "owasp": "M4:2023"}


def rule_unmanaged_sw(s):
    sw = s.get("sw_register_calls") or []
    if not sw or s.get("sw_controller_set"): return None
    return {"name": f"ServiceWorker.register() in {len(sw)} bundle(s) without ServiceWorkerController",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-668", "owasp": "M4:2023",
            "evidence": "Files: " + ", ".join(sw[:6]),
            "remediation": "Configure WebView ServiceWorkerController + ServiceWorkerClient.shouldInterceptRequest to control SW fetches; otherwise the SW persists + intercepts every WebView request."}


SERVICE_WORKER_AUDIT_FINDING_RULES = [rule_positive_emit, rule_unmanaged_sw]
