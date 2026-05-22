"""BFS Crawler — findings rules library."""

def rule_total_urls(s):
    n = s.get("total") or 0
    if n == 0: return None
    return {"name": f"{n} URL(s) crawled",
            "severity": "INFO",
            "evidence": f"Same-origin link graph with {s.get('depth_reached', '?')} hops"}


def rule_forms_found(s):
    n = len(s.get("forms") or [])
    if n == 0: return None
    return {"name": f"{n} form(s) discovered",
            "severity": "INFO",
            "evidence": f"Total HTML forms found across crawl"}


def rule_login_forms(s):
    li = s.get("login_forms") or []
    if not li: return None
    return {"name": f"Login form(s) found ({len(li)})",
            "severity": "INFO",
            "evidence": f"Login at: {', '.join(li[:3])}"}


def rule_upload_forms(s):
    up = s.get("upload_forms") or []
    if not up: return None
    return {"name": f"File-upload endpoints found ({len(up)})",
            "severity": "MEDIUM",
            "cwe": "CWE-434",
            "evidence": f"Upload at: {', '.join(up[:3])}",
            "remediation": "File uploads are high-risk — validate file type via magic bytes (not extension), store outside web root, scan for malware, generate unique filenames, enforce size limits."}


def rule_external_domains(s):
    ext = s.get("external_domains") or []
    if not ext: return None
    return {"name": f"{len(ext)} external domain(s) linked",
            "severity": "INFO",
            "evidence": f"Linked: {', '.join(list(ext)[:5])}"}


def rule_hidden_inputs(s):
    n = s.get("hidden_input_count") or 0
    if n == 0: return None
    return {"name": f"{n} hidden form input(s) discovered",
            "severity": "INFO",
            "evidence": "Hidden inputs often contain CSRF tokens, session IDs, or business logic state"}


CRAWL_FINDING_RULES = [
    rule_total_urls, rule_forms_found, rule_login_forms,
    rule_upload_forms, rule_external_domains, rule_hidden_inputs,
]
