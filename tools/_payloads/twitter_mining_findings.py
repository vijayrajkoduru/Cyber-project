"""twitter_mining — findings rules."""
def rule_found(s):
    h = s.get("tw_handle_count") or 0
    t = s.get("tw_tweet_count") or 0
    if h + t == 0: return None
    return {"name":f"Twitter/X mentions: {h} handle(s), {t} tweet(s)","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":f"Handles: {s.get('tw_handles','')}. Tweets: {s.get('tw_tweet_sample','')}",
            "remediation":"Public Twitter/X mentions reveal customer sentiment, employee identities, sometimes leaked internal links. Useful for OSINT context."}

def rule_none(s):
    if (s.get("tw_handle_count") or 0) + (s.get("tw_tweet_count") or 0) > 0: return None
    return {"name":"No Twitter/X presence found","severity":"POSITIVE",
            "evidence":"site:twitter.com + site:x.com returned no matches",
            "remediation":"Low social-media OSINT footprint.",
            "cwe":"CWE-200","owasp":"M2:2023"}

TWITTER_MINING_FINDING_RULES = [rule_found, rule_none]
