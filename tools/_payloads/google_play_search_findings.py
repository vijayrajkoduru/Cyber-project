"""google_play_search findings."""

def rule_f(s):
    c = s.get("pkg_count") or 0
    if c == 0: return None
    return {"name":f"Google Play apps: {c} package(s)","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":s.get("pkg_sample",""),
            "remediation":"Mobile apps expand attack surface. Each app should be audited (mobile_static, mobile_storage modules)."}
def rule_n(s):
    if (s.get("pkg_count") or 0) > 0: return None
    return {"name":"No Google Play apps found","severity":"POSITIVE",
            "evidence":"Play Store search returned empty","remediation":"No mobile attack surface via Play Store.",
            "cwe":"CWE-200","owasp":"M2:2023"}
GOOGLE_PLAY_SEARCH_FINDING_RULES = [rule_f, rule_n]
