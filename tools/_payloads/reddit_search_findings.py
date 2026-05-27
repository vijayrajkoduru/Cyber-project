"""reddit_search — findings rules."""
def rule_found(s):
    c = s.get("reddit_count") or 0
    if c == 0: return None
    return {"name":f"Reddit mentions: {c} post(s) in {s.get('reddit_subreddits','').count(',')+1 if s.get('reddit_subreddits') else 0} subreddit(s)","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":f"Top: {s.get('reddit_top_post','?')}. Subs: {s.get('reddit_subreddits','')}",
            "remediation":"Public Reddit discussions reveal product perception + user-side issues (account problems, support gaps, sometimes credential leaks). Monitor with a saved search."}

def rule_none(s):
    if (s.get("reddit_count") or 0) > 0: return None
    return {"name":"No Reddit mentions for this domain","severity":"POSITIVE",
            "evidence":"Reddit search API returned no posts",
            "remediation":"No public Reddit chatter — neutral signal.",
            "cwe":"CWE-200","owasp":"M2:2023"}

REDDIT_SEARCH_FINDING_RULES = [rule_found, rule_none]
