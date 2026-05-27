"""common_crawl — findings rules."""
def rule_found(s):
    if not s.get("common_crawl_found"): return None
    return {"name":f"Common Crawl indexed {s.get('url_count',0)} URL(s) for this domain","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":f"index={s.get('cc_index','?')}. Sample: {s.get('urls_sample','')}",
            "remediation":"Common Crawl is public + searchable. Audit indexed URLs for sensitive paths (admin panels, debug endpoints, leaked params)."}

def rule_not_found(s):
    if s.get("common_crawl_found"): return None
    return {"name":"No Common Crawl entries","severity":"INFO",
            "evidence":"CC indexes returned empty",
            "remediation":"Domain either not crawled or blocks CC user-agent.",
            "cwe":"CWE-200","owasp":"M2:2023"}

COMMON_CRAWL_FINDING_RULES = [rule_found, rule_not_found]
