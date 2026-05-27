"""linkedin_employees — findings rules."""
def rule_found(s):
    c = s.get("li_employee_count") or 0
    if c == 0: return None
    return {"name":f"LinkedIn employee enum: {c} profile(s) discovered","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":f"Sample slugs: {s.get('li_employees_sample','')}. Company: {s.get('li_company_pages','')}",
            "remediation":"Employee profiles enable spear-phishing pretexts (name + role + tech stack). Consider LinkedIn privacy controls + employee phishing training."}

def rule_none(s):
    if (s.get("li_employee_count") or 0) > 0: return None
    return {"name":"No LinkedIn profiles found for this domain keyword","severity":"POSITIVE",
            "evidence":f"DuckDuckGo+Bing site:linkedin.com/in for '{s.get('li_keyword','')}' returned 0",
            "remediation":"Low LinkedIn exposure reduces spear-phishing surface.",
            "cwe":"CWE-200","owasp":"M2:2023"}

LINKEDIN_EMPLOYEES_FINDING_RULES = [rule_found, rule_none]
