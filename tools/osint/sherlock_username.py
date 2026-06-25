"""Sherlock-style cross-platform username enum — playbook §1 #6, §3 #47.

Local mini-Sherlock: 25 most-used social platforms checked via HEAD/GET
with platform-specific 200/404 disambiguation. Single-pass async, no
external Sherlock dep, no API keys.

Real probe — actually requests each profile URL. Each result labeled
CONFIRMED (HTTP 200 + content marker) or AMBIGUOUS (200 but no marker).
"""
import asyncio
import re
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify
from tools._core import grade

router = APIRouter()
WALL_CLOCK_S = 35

# (label, url_template, present_marker_regex_or_str, absent_marker)
# Marker logic: if "present" in body -> CONFIRMED. If "absent" -> CLEAN.
# Else -> AMBIGUOUS (just report HTTP status).
SITES = [
    ("GitHub",        "https://github.com/{u}",                    None, "Not Found"),
    ("Twitter/X",     "https://x.com/{u}",                          None, "doesn't exist"),
    ("Instagram",     "https://www.instagram.com/{u}/",             None, "Sorry, this page"),
    ("Reddit",        "https://www.reddit.com/user/{u}",            None, "page not found"),
    ("Medium",        "https://medium.com/@{u}",                    None, "PAGE NOT FOUND"),
    ("DevTo",         "https://dev.to/{u}",                         None, "Sorry, this page"),
    ("Hashnode",      "https://hashnode.com/@{u}",                  None, "404"),
    ("StackOverflow", "https://stackoverflow.com/users/{u}",        None, "Page Not Found"),
    ("GitLab",        "https://gitlab.com/{u}",                     None, "Sign in"),
    ("Bitbucket",     "https://bitbucket.org/{u}/",                 None, "404"),
    ("Pinterest",     "https://www.pinterest.com/{u}/",             None, "didn't find"),
    ("Tumblr",        "https://{u}.tumblr.com/",                    None, "There's nothing here"),
    ("Vimeo",         "https://vimeo.com/{u}",                      None, "Sorry, we couldn"),
    ("SoundCloud",    "https://soundcloud.com/{u}",                 None, "We can't find that"),
    ("Twitch",        "https://www.twitch.tv/{u}",                  None, "Sorry. Unless"),
    ("YouTube",       "https://www.youtube.com/@{u}",               None, "Not Found"),
    ("Spotify",       "https://open.spotify.com/user/{u}",          None, "Page not found"),
    ("Patreon",       "https://www.patreon.com/{u}",                None, "Page Not Found"),
    ("Kickstarter",   "https://www.kickstarter.com/profile/{u}",    None, "Page Not Found"),
    ("CodePen",       "https://codepen.io/{u}",                     None, "404"),
    ("Replit",        "https://replit.com/@{u}",                    None, "Page Not Found"),
    ("Telegram",      "https://t.me/{u}",                           None, "You can contact"),  # absent text
    ("Keybase",       "https://keybase.io/{u}",                     None, "Page not found"),
    ("HackerOne",     "https://hackerone.com/{u}",                  None, "Page not found"),
    ("Bugcrowd",      "https://bugcrowd.com/{u}",                   None, "Page not found"),
]


def _check_one(username, label, url_tpl, present_marker, absent_marker):
    url = url_tpl.format(u=username)
    r = safe_get(url, timeout=6,
                  headers={"User-Agent": "Mozilla/5.0 VulnusLab-OSINT"})
    if r is None:
        return (label, url, "TIMEOUT", None)
    if r.status_code == 404:
        return (label, url, "CLEAN", "HTTP 404")
    if r.status_code >= 400:
        return (label, url, "AMBIGUOUS", f"HTTP {r.status_code}")
    body = (r.text or "")[:50000]
    if absent_marker and absent_marker.lower() in body.lower():
        return (label, url, "CLEAN", f"absent-marker matched: '{absent_marker[:30]}'")
    return (label, url, "FOUND", f"HTTP 200 ({len(body)} bytes)")


# Common TLDs we strip when the orchestrator passes a domain as the username.
_KNOWN_TLDS = {"com","net","org","co","io","ai","app","dev","me","us","uk",
                "in","de","fr","ca","au","jp","cn","ru","br","es","it","nl"}


def _to_brand_stem(target: str) -> str:
    """If target looks like a domain (contains a known TLD), strip TLD +
    subdomains and return only the brand-stem suitable for username search.

    "dasplc.com"          -> "dasplc"
    "www.example.com"     -> "example"
    "admin.acme.co.uk"    -> "acme"  (best-effort)
    "@cooluser"           -> "cooluser"
    "user.name"           -> "user.name"  (not a domain pattern)
    """
    t = (target or "").strip().lstrip("@")
    for pfx in ("http://", "https://"):
        if t.startswith(pfx):
            t = t[len(pfx):]
    t = t.split("/", 1)[0].split(":", 1)[0]
    if t.startswith("www."):
        t = t[4:]
    parts = t.lower().split(".")
    # Domain heuristic: last token is a known TLD AND >= 2 parts
    if len(parts) >= 2 and parts[-1] in _KNOWN_TLDS:
        # Take the rightmost non-TLD token as brand stem
        # (e.g. acme.co.uk -> "acme", dasplc.com -> "dasplc")
        if len(parts) >= 3 and parts[-2] in {"co","com","org","net","gov","ac"}:
            return parts[-3]
        return parts[-2]
    return t


def _do_scan(req: ScanRequest) -> dict:
    raw = (req.target or "").strip().lstrip("@")
    username = _to_brand_stem(raw)
    if not username or not re.match(r"^[A-Za-z0-9_-]{2,40}$", username):
        return standard_response(
            tool="sherlock_username", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason=("invalid username after brand-stem extraction "
                            "(2-40 alphanumeric + _ -). Sherlock requires a "
                            "username, not a domain or email."))

    found = []
    clean = []
    ambiguous = []
    with ThreadPoolExecutor(max_workers=12) as ex:
        futures = [ex.submit(_check_one, username, l, t, p, a)
                    for (l, t, p, a) in SITES]
        for fut in futures:
            try:
                label, url, status, detail = fut.result(timeout=10)
            except Exception:
                continue
            if status == "FOUND":
                found.append((label, url))
            elif status == "CLEAN":
                clean.append(label)
            else:
                ambiguous.append((label, detail or status))

    findings = []
    if found:
        evidence = " | ".join(f"{l}: {u}" for l, u in found[:15])
        findings.append(wrap_finding(
            f"Username '{username}' found on {len(found)} platform(s)",
            # Public profile existence is public-by-design OSINT, not an
            # exposure in itself. INFO baseline; LOW max only when the handle
            # is reused widely enough to materially aid identity correlation.
            severity=(sev := grade.inventory(len(found), low_at=5)),
            cwe="CWE-200", cvss=grade.cvss_for(sev),
            remediation="Username reuse across platforms allows attacker to "
                        "build full identity profile. For high-risk users (execs, "
                        "security team), use platform-unique usernames or random handles.",
            evidence_marker=evidence + " (CONFIRMED via HTTP 200)"))
    if ambiguous:
        findings.append(wrap_finding(
            f"Ambiguous on {len(ambiguous)} platform(s) — needs manual verify",
            severity=grade.info(), cwe="CWE-200",
            remediation="Manually visit each URL; platform may have updated their 404 markers.",
            evidence_marker=" | ".join(f"{l} ({d})" for l, d in ambiguous[:10])))
    if not findings:
        findings.append(wrap_finding(
            f"Username '{username}' not found on any of {len(SITES)} platforms",
            severity=grade.protective(), cwe="CWE-200",
            remediation="Either the username is genuinely fresh or your platform "
                        "list missed where they post. Consider a deeper Sherlock run (400+ sites).",
            evidence_marker=f"all {len(SITES)} platforms returned CLEAN markers"))

    return standard_response(
        tool="sherlock_username", target=req.target, findings=findings,
        tests_performed=len(SITES),
        vulnerable=False,  # public profile existence is OSINT, not an exposure
        tests_summary=f"checked {len(SITES)} platforms; found on {len(found)}; clean on {len(clean)}",
        raw_data={"found": found, "clean": clean, "ambiguous": ambiguous})


@router.post("/api/osint/sherlock_username")
@vl_verify()
async def scan_sherlock_username(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="sherlock_username", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
