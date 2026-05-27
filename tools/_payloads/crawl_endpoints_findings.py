"""crawl_endpoints findings."""

def rule_f(s):
    c = s.get("urls_found") or 0
    return {"name":f"BFS crawl: {c} URL(s) discovered across {s.get('pages_crawled',0)} pages","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":s.get("url_sample",""),
            "remediation":"Crawled URLs become input for webapp scanners (XSS, SQLi, IDOR, etc)."}
CRAWL_ENDPOINTS_FINDING_RULES = [rule_f]
