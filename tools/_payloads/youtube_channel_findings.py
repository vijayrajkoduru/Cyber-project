"""youtube_channel — findings rules."""
def rule_found(s):
    c = s.get("yt_channel_count") or 0
    v = s.get("yt_video_count") or 0
    if c + v == 0: return None
    return {"name":f"YouTube presence: {c} channel(s), {v} video(s) mentioning domain","severity":"POSITIVE",
            "cwe":"CWE-200","owasp":"M2:2023",
            "evidence":f"Channels: {s.get('yt_channels','')}",
            "remediation":"Corporate videos can leak office interior shots, employee names, product demos, sometimes admin UIs. Audit content for sensitive visuals."}

def rule_none(s):
    if (s.get("yt_channel_count") or 0) + (s.get("yt_video_count") or 0) > 0: return None
    return {"name":"No YouTube presence found","severity":"POSITIVE",
            "evidence":"site:youtube.com returned no matches",
            "remediation":"No video-OSINT footprint.",
            "cwe":"CWE-200","owasp":"M2:2023"}

YOUTUBE_CHANNEL_FINDING_RULES = [rule_found, rule_none]
