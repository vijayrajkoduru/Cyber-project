"""pending_intent_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("pending_intent_audit_total"):
        return None
    return {"name": "PendingIntent + task-affinity posture clean",
            "severity": "POSITIVE",
            "evidence": (f"Immutable callers={s.get('immutable_pending_callers', 0)} "
                         f"mutable=0 task-tricks=0"),
            "remediation": "Continue using FLAG_IMMUTABLE on every PendingIntent and unique taskAffinity.",
            "cwe": "CWE-927", "owasp": "M4:2023"}


def rule_mutable(s):
    m = s.get("mutable_pending_callers") or []
    if not m: return None
    return {"name": f"PendingIntent.FLAG_MUTABLE in {len(m)} class(es)",
            "severity": "HIGH", "cvss": "7.0",
            "cwe": "CWE-927", "owasp": "M4:2023",
            "evidence": "Files: " + ", ".join(m[:6]),
            "remediation": ("Replace FLAG_MUTABLE with FLAG_IMMUTABLE. Mutable PendingIntents let the "
                            "receiving app rewrite extras / action / data (Strandhogg-class hijack).")}


def rule_task_hijack(s):
    t = s.get("task_hijack_suspects") or []
    if not t: return None
    return {"name": f"StrandHogg-class task-affinity / launchMode tricks in {len(t)} manifest(s)",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-940", "owasp": "M4:2023",
            "evidence": "Files: " + ", ".join(t[:6]),
            "remediation": ("Use taskAffinity=\"\" (empty string) on all activities + launchMode=\"standard\". "
                            "StrandHogg 2.0 exploits non-empty taskAffinity + allowTaskReparenting to mount "
                            "overlay attacks.")}


PENDING_INTENT_AUDIT_FINDING_RULES = [rule_positive_emit, rule_mutable, rule_task_hijack]
