"""strandhogg_audit — findings rules."""


def rule_positive_emit(s):
    n = s.get("strandhogg_audit_total", 0)
    if n > 0: return None
    mains = len(s.get("main_launcher_activities") or [])
    return {"name": f"Launcher activities properly task-isolated ({mains} MAIN)",
            "severity": "POSITIVE",
            "cwe": "CWE-940", "owasp": "M3:2023",
            "evidence": f"{mains} MAIN/LAUNCHER activities, 0 with risky task affinity",
            "remediation": "Maintain. New launcher activities should use "
                           "launchMode='singleInstance' or 'singleTask' with "
                           "taskAffinity=''."}


def rule_strandhogg_risky(s):
    risky = s.get("risky_launcher_configs") or []
    if not risky: return None
    return {"name": f"StrandHogg-vulnerable launcher config ({len(risky)} activity/ies)",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-940", "owasp": "M3:2023",
            "evidence": " | ".join(
                f"{r['name']} (launchMode={r['launchMode']}, taskAffinity={r['taskAffinity']})"
                for r in risky[:3]
            ),
            "remediation": "Mitigate StrandHogg 1 + 2.0 task hijack: "
                           "(1) set android:taskAffinity='' on launcher activities, "
                           "(2) set android:launchMode='singleInstance' (preferred for "
                           "single-window apps) or 'singleTask', "
                           "(3) set android:allowTaskReparenting='false'. "
                           "Apps NOT patched have lost banking creds via fake-overlay "
                           "task-hijack since 2019 (CVE-2020-0096, 36+ malware in Play 2020)."}
