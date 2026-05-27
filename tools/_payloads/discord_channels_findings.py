"""discord_channels findings."""

def rule_f(s):
    if (s.get("disc_count") or 0) == 0: return None
    return {"name":f"Discord invite links: {s.get('disc_count',0)} found","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":s.get("disc_sample",""),
            "remediation":"Public Discord communities reveal user-base + sometimes leak internal info via support channels."}
def rule_n(s):
    if (s.get("disc_count") or 0) > 0: return None
    return {"name":"No Discord communities","severity":"POSITIVE",
            "evidence":"No invite links found","remediation":"No public Discord presence.",
            "cwe":"CWE-200","owasp":"M2:2023"}
DISCORD_CHANNELS_FINDING_RULES = [rule_f, rule_n]
