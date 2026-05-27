"""telegram_channels findings."""

def rule_f(s):
    if (s.get("tg_count") or 0) == 0: return None
    return {"name":f"Telegram channels: {s.get('tg_count',0)} found","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":s.get("tg_sample",""),
            "remediation":"Public Telegram channels often serve as support/community hubs; sometimes leak internal docs."}
def rule_n(s):
    if (s.get("tg_count") or 0) > 0: return None
    return {"name":"No Telegram channels","severity":"POSITIVE",
            "evidence":"No t.me matches","remediation":"No Telegram OSINT footprint.",
            "cwe":"CWE-200","owasp":"M2:2023"}
TELEGRAM_CHANNELS_FINDING_RULES = [rule_f, rule_n]
