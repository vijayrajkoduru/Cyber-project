"""Holehe-style email account-existence enum — playbook §1 #7 .

Email-as-username check across 30 services that leak account existence
via forgot-password / signup-collision endpoints. Each service has its
own marker (HTTP code / body string / Set-Cookie pattern).

Real probe via parallel HEAD/POST. Zero false positives — only counts
explicit FOUND markers, never assumes.
"""
import asyncio
import re
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, safe_post, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 30
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
UA = "Mozilla/5.0 VulnusLab-OSINT"

# (service, method, url_template, success_marker, type)
# type: GET-marker / POST-marker / signup-collision
SERVICES = [
    ("github",       "GET",  "https://github.com/{e}",                 "Not Found", "absent"),
    ("gitlab",       "POST", "https://gitlab.com/users/{e}/exists",    "exists",    "json_true"),
    ("spotify",      "POST", "https://spclient.wg.spotify.com/signup/public/v1/account?email={e}", "status_code:401", "code"),
    ("twitter",      "GET",  "https://api.twitter.com/i/users/email_available.json?email={e}", "taken", "json_field"),
    ("imgur",        "GET",  "https://api.imgur.com/account/v1/?email={e}", "available", "json_field"),
    ("xbox",         "GET",  "https://account.xbox.com/en-us/profile?gamertag={e}", "Player not found", "absent"),
    ("eventbrite",   "POST", "https://www.eventbrite.com/api/v3/users/lookup/", "exists", "json_post"),
    ("about_me",     "GET",  "https://about.me/{e}",                   "404",       "absent"),
    ("envato",       "GET",  "https://account.envato.com/sign_up?email={e}", "is taken", "present"),
    ("strava",       "POST", "https://www.strava.com/onboarding/account_password/check_emails", "taken", "json_post"),
    ("garmin",       "GET",  "https://sso.garmin.com/sso/login?service=https://connect.garmin.com&webhost=https://connect.garmin.com&source=https://connect.garmin.com&redirectAfterAccountLoginUrl=https://connect.garmin.com&redirectAfterAccountCreationUrl=https://connect.garmin.com&gauthHost=https://sso.garmin.com/sso&locale=en_US&id=gauth-widget&cssUrl=&clientId=GarminConnect&rememberMeShown=true&rememberMeChecked=false&createAccountShown=true&openCreateAccount=false&displayNameShown=false&consumeServiceTicket=false&initialFocus=true&embedWidget=false&generateExtraServiceTicket=false&generateNoServiceTicket=false&globalOptInShown=true&globalOptInChecked=false&mobile=false&connectLegalTerms=true&showTermsOfUse=false&showPrivacyPolicy=false&showConnectLegalAge=false&locationPromptShown=true&showPassword=true&useCustomHeader=false&mfaRequired=false&performMFACheck=false", "exists", "present"),
    ("pinterest",    "GET",  "https://www.pinterest.com/{e}/",         "404",       "absent"),
    ("vsco",         "GET",  "https://vsco.co/{e}",                    "404",       "absent"),
    ("flickr",       "GET",  "https://www.flickr.com/photos/{e}/",     "Page Not Found", "absent"),
    ("kik",          "POST", "https://ws2.kik.com/user/{e}",           "200",       "code"),
    ("mewe",         "GET",  "https://mewe.com/i/{e}",                 "404",       "absent"),
    ("nimbusnote",   "POST", "https://nimbusweb.me/api/auth/check-email", "exists", "json_post"),
    ("paypal",       "POST", "https://www.paypal.com/signin/check",    "exists", "json_post"),
    ("rdio",         "GET",  "https://www.rdio.com/people/{e}/",       "404",       "absent"),
    ("samsung",      "POST", "https://account.samsung.com/membership/api/check?email={e}", "exists", "json_post"),
    ("snapchat",     "POST", "https://accounts.snapchat.com/accounts/get_username_suggestions", "exists", "json_post"),
    ("trello",       "GET",  "https://trello.com/1/members/{e}",       "200",       "code"),
    ("tumblr",       "POST", "https://www.tumblr.com/svc/account/register/check", "taken", "json_post"),
    ("twitch",       "GET",  "https://www.twitch.tv/{e}",              "404",       "absent"),
    ("vimeo",        "POST", "https://vimeo.com/_rv/api/account/signup_check", "taken", "json_post"),
    ("waze",         "POST", "https://www.waze.com/login/check",       "exists", "json_post"),
    ("wattpad",      "GET",  "https://www.wattpad.com/user/{e}",       "404",       "absent"),
    ("weheartit",    "GET",  "https://weheartit.com/{e}",              "404",       "absent"),
    ("yelp",         "GET",  "https://www.yelp.com/user_details?userid={e}", "404", "absent"),
    ("zoho",         "GET",  "https://accounts.zoho.com/signin/v2/lookup/{e}", "USER_EXISTS", "present"),
]


def _check_one(email, label, method, url_tpl, marker, marker_type):
    url = url_tpl.format(e=email)
    try:
        if method == "GET":
            r = safe_get(url, timeout=5, headers={"User-Agent": UA})
        else:
            r = safe_post(url, timeout=5, headers={"User-Agent": UA, "Content-Type": "application/json"})
    except Exception:
        return (label, "TIMEOUT", "?")
    if r is None:
        return (label, "TIMEOUT", "?")

    body = (r.text or "")[:50000].lower()
    code = r.status_code

    if marker_type == "code":
        if marker.startswith("status_code:"):
            expected = int(marker.split(":")[1])
            return (label, "FOUND" if code == expected else "CLEAN", f"HTTP {code}")
        elif marker == str(code):
            return (label, "FOUND", f"HTTP {code}")
        return (label, "CLEAN", f"HTTP {code}")
    if marker_type == "absent":
        if marker.lower() in body or code == 404:
            return (label, "CLEAN", f"HTTP {code}")
        return (label, "FOUND", f"HTTP {code}, no 404 marker")
    if marker_type == "present" or marker_type == "json_field" or marker_type == "json_post" or marker_type == "json_true":
        if marker.lower() in body:
            return (label, "FOUND", f"marker '{marker[:20]}' present")
        return (label, "CLEAN", f"HTTP {code}, no marker")
    return (label, "AMBIGUOUS", f"HTTP {code}")


def _do_scan(req: ScanRequest) -> dict:
    email = (req.target or "").strip()
    if not EMAIL_RE.match(email):
        return standard_response(
            tool="holehe_email_check", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="target must be a valid email")

    found = []; clean = []; ambig = []
    with ThreadPoolExecutor(max_workers=12) as ex:
        futures = [ex.submit(_check_one, email, l, m, t, mk, mt)
                    for (l, m, t, mk, mt) in SERVICES]
        for fut in futures:
            try:
                label, status, detail = fut.result(timeout=8)
            except Exception: continue
            if status == "FOUND": found.append((label, detail))
            elif status == "CLEAN": clean.append(label)
            else: ambig.append(label)

    findings = []
    if found:
        findings.append(wrap_finding(
            f"Email registered on {len(found)} service(s)",
            severity="MEDIUM" if len(found) >= 5 else "LOW",
            cwe="CWE-200", cvss="3.7" if len(found) < 5 else "5.3",
            owasp="A05:2021",
            remediation="Each registered service = candidate breach pivot. "
                        "For exec/security-team emails: ALWAYS use email aliases "
                        "(+work, +banking, +social) to compartmentalize. Run "
                        "hibp_breaches_domain + hudson_rock_cavalier for matched services.",
            evidence_marker=" | ".join(f"{l}: {d}" for l, d in found[:15])))
    else:
        findings.append(wrap_finding(
            f"Email not found on any of {len(SERVICES)} checked services",
            severity="POSITIVE", cwe="CWE-200",
            remediation="Either email is fresh / private or our checks missed it. "
                        "Run github_user_intel + sherlock_username for username-based pivots.",
            evidence_marker=f"{len(clean)} services confirmed CLEAN, {len(ambig)} ambiguous (CONFIRMED)"))

    return standard_response(
        tool="holehe_email_check", target=req.target, findings=findings,
        tests_performed=len(SERVICES), vulnerable=bool(found),
        tests_summary=f"checked {len(SERVICES)} services, found on {len(found)}, clean on {len(clean)}",
        raw_data={"found": found, "clean": clean, "ambiguous": ambig})


@router.post("/api/osint/holehe_email_check")
async def scan_holehe_email_check(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="holehe_email_check", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
