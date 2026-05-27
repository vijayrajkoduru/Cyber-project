"""facebook_instagram findings."""

def rule_f(s):
    if (s.get("fb_count") or 0) + (s.get("ig_count") or 0) == 0: return None
    return {"name":f"Facebook/Instagram presence (FB:{s.get('fb_count',0)}, IG:{s.get('ig_count',0)})","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":f"FB: {s.get('fb_sample','')}; IG: {s.get('ig_sample','')}",
            "remediation":"Social profiles reveal employee identities + corporate events. Useful for phishing pretexts."}
def rule_n(s):
    if (s.get("fb_count") or 0) + (s.get("ig_count") or 0) > 0: return None
    return {"name":"No Facebook/Instagram presence","severity":"POSITIVE",
            "evidence":"No social profile matches","remediation":"Reduced social-OSINT footprint.",
            "cwe":"CWE-200","owasp":"M2:2023"}
FACEBOOK_INSTAGRAM_FINDING_RULES = [rule_f, rule_n]
