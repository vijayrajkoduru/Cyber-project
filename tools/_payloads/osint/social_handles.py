"""social_handles — 12 platforms × handle variations for OSINT footprinting.

Generated 2026-05-24 by claude-sonnet-4-6.
Refresh cadence: quarterly (platform URL schemes are stable).
Source: Sherlock + Maigret + Holehe — top-12 highest-coverage platforms.

Each entry: (platform_name, url_template, success_marker_in_response).
Scanner probes each URL with HEAD; 200 = handle exists, 404 = available.
"""

SOCIAL_PLATFORMS = [
    # (name, url_template, http_success_codes_indicating_account_exists)
    ("GitHub",      "https://github.com/{handle}",                   [200]),
    ("X (Twitter)", "https://twitter.com/{handle}",                  [200]),
    ("Reddit",      "https://www.reddit.com/user/{handle}",          [200]),
    ("Instagram",   "https://www.instagram.com/{handle}/",           [200]),
    ("LinkedIn",    "https://www.linkedin.com/in/{handle}",          [200, 999]),
    ("YouTube",     "https://www.youtube.com/@{handle}",             [200]),
    ("TikTok",      "https://www.tiktok.com/@{handle}",              [200]),
    ("Medium",      "https://medium.com/@{handle}",                  [200]),
    ("Mastodon",    "https://mastodon.social/@{handle}",             [200]),
    ("Twitch",      "https://www.twitch.tv/{handle}",                [200]),
    ("Pinterest",   "https://www.pinterest.com/{handle}/",           [200]),
    ("Pastebin",    "https://pastebin.com/u/{handle}",               [200]),
]

# Handle generation patterns from a target domain
# e.g. target=acme.com → acme, acmecorp, acme_official, acmehq, ...
def derive_handles(target: str) -> list[str]:
    """Generate 6 likely org handles from a target domain."""
    base = target.lower().replace("http://", "").replace("https://", "")
    base = base.split("/")[0].split(":")[0]
    org = base.split(".")[0]  # acme.com → acme
    if not org or len(org) < 2:
        return []
    return [
        org,
        f"{org}corp",
        f"{org}hq",
        f"{org}official",
        f"{org}_inc",
        f"the{org}",
    ]
