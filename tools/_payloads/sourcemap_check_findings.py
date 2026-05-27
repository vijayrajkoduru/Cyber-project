"""sourcemap_check findings."""

def rule_f(s):
    c = s.get("sm_count") or 0
    if c == 0: return None
    return {"name":f"Source maps publicly exposed ({c} .map files)","severity":"HIGH","cvss":"6.5",
            "cwe":"CWE-540","owasp":"M9:2023",
            "evidence":s.get("sm_sample",""),
            "remediation":"Source maps leak original source code. Either disable .map generation in production builds, or exclude /*.js.map from web server config."}
def rule_n(s):
    if (s.get("sm_count") or 0) > 0: return None
    return {"name":"No source maps exposed","severity":"POSITIVE",
            "evidence":"No accessible .map files","remediation":"Maintain.",
            "cwe":"CWE-540","owasp":"M9:2023"}
SOURCEMAP_CHECK_FINDING_RULES = [rule_f, rule_n]
