"""Sherlock-equivalent — username enumeration across 30 social platforms via aiohttp."""
import asyncio
import aiohttp
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota

router = APIRouter()


PLATFORMS = [
    ("GitHub","https://github.com/{u}","200"),
    ("Twitter/X","https://twitter.com/{u}","200"),
    ("Instagram","https://instagram.com/{u}","200"),
    ("Reddit","https://www.reddit.com/user/{u}","200"),
    ("Medium","https://medium.com/@{u}","200"),
    ("StackOverflow","https://stackoverflow.com/users/{u}","200"),
    ("HackerNews","https://news.ycombinator.com/user?id={u}","200"),
    ("DEV.to","https://dev.to/{u}","200"),
    ("Pinterest","https://pinterest.com/{u}","200"),
    ("Vimeo","https://vimeo.com/{u}","200"),
    ("YouTube","https://youtube.com/@{u}","200"),
    ("Twitch","https://twitch.tv/{u}","200"),
    ("SoundCloud","https://soundcloud.com/{u}","200"),
    ("Spotify","https://open.spotify.com/user/{u}","200"),
    ("Patreon","https://patreon.com/{u}","200"),
    ("Behance","https://behance.net/{u}","200"),
    ("Dribbble","https://dribbble.com/{u}","200"),
    ("CodePen","https://codepen.io/{u}","200"),
    ("GitLab","https://gitlab.com/{u}","200"),
    ("Bitbucket","https://bitbucket.org/{u}","200"),
    ("Replit","https://replit.com/@{u}","200"),
    ("Goodreads","https://goodreads.com/{u}","200"),
    ("Letterboxd","https://letterboxd.com/{u}","200"),
    ("Steam","https://steamcommunity.com/id/{u}","200"),
    ("Mastodon","https://mastodon.social/@{u}","200"),
    ("Telegram","https://t.me/{u}","200"),
    ("Keybase","https://keybase.io/{u}","200"),
    ("HackTheBox","https://www.hackthebox.com/{u}","200"),
    ("TryHackMe","https://tryhackme.com/p/{u}","200"),
    ("Quora","https://www.quora.com/profile/{u}","200"),
]


async def _check(session, platform, url_tmpl, success, username):
    url = url_tmpl.format(u=username)
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8),
                               allow_redirects=True,
                               headers={"User-Agent": "Mozilla/5.0 VulnusLab"}) as r:
            if success == "200":
                return {"platform": platform, "url": url, "found": r.status == 200}
            text = await r.text()
            return {"platform": platform, "url": url, "found": success in text}
    except Exception:
        return {"platform": platform, "url": url, "found": None, "error": "timeout"}


@router.post("/api/osint/sherlock")
async def osint_sherlock(req: ScanRequest, _=Depends(verify_scan_quota)):
    username = (req.target or "").strip().lstrip("@")
    if not username or len(username) < 2 or "." in username:
        return {"ok": False,
                "skipped_reason": "Need a username (2+ chars, no dots) — Sherlock is username-based, not domain."}
    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(*[_check(session, p, u, sc, username) for p, u, sc in PLATFORMS])
    found = [r for r in results if r.get("found") is True]
    return {"ok": True, "username": username,
            "platforms_checked": len(PLATFORMS),
            "accounts_found": found, "total_found": len(found),
            "engine": f"pure-Python aiohttp, {len(PLATFORMS)} platforms in parallel"}


def register(app):
    app.include_router(router)
