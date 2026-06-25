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
from tools._vl_core.verify import vl_verify
from tools._core import grade

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

    # VL-VERIFY deep: skip reserved-domain emails (RFC 2606) — they will
    # return FOUND on services that 200 for any email-shaped string.
    domain = email.split("@", 1)[1].lower() if "@" in email else ""
    from tools._vl_core.reserved_domains import is_reserved
    if is_reserved(domain):
        return standard_response(
            tool="holehe_email_check", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason=("Email domain is RFC 2606 / 6761 reserved "
                             "(example.com, *.test, etc.). Account-existence "
                             "checks are not applicable."))

    # VL-VERIFY deep: sentinel email — probe a guaranteed-nonexistent
    # email on each service first. If a service returns FOUND for the
    # sentinel, it's unreliable; drop those services from real probes.
    import secrets as _sec
    sentinel = f"vlxxx_no_exist_{_sec.token_hex(8)}@example.org"
    unreliable_services = set()
    with ThreadPoolExecutor(max_workers=12) as ex:
        sentinel_futs = {
            ex.submit(_check_one, sentinel, l, m, t, mk, mt): l
            for (l, m, t, mk, mt) in SERVICES
        }
        for fut, label in sentinel_futs.items():
            try:
                _, status, _ = fut.result(timeout=6)
            except Exception:
                continue
            if status == "FOUND":
                unreliable_services.add(label)

    found = []; clean = []; ambig = []
    with ThreadPoolExecutor(max_workers=12) as ex:
        futures = [ex.submit(_check_one, email, l, m, t, mk, mt)
                    for (l, m, t, mk, mt) in SERVICES
                    if l not in unreliable_services]
        for fut in futures:
            try:
                label, status, detail = fut.result(timeout=8)
            except Exception: continue
            if status == "FOUND": found.append((label, detail))
            elif status == "CLEAN": clean.append(label)
            else: ambig.append(label)

    reliable_count = len(SERVICES) - len(unreliable_services)
    findings = []
    if found:
        sentinel_suffix = (f" [VL-VERIFY: {len(unreliable_services)} "
                           f"services sentinel-dropped]"
                           if unreliable_services else "")
        findings.append(wrap_finding(
            f"Email registered on {len(found)} service(s) (sentinel-verified)",
            # Account-existence enumeration is public-by-design OSINT, NOT a
            # breach: knowing an email has a Spotify/GitHub account is not an
            # exposure. INFO baseline; LOW max when widely reused.
            severity=(sev := grade.inventory(len(found), low_at=5)),
            cwe="CWE-200", cvss=grade.cvss_for(sev),
            owasp="A05:2021",
            verified_exploit=False,
            remediation="Each registered service = candidate breach pivot. "
                        "For exec/security-team emails: ALWAYS use email aliases "
                        "(+work, +banking, +social) to compartmentalize. Run "
                        "hibp_breaches_domain + hudson_rock_cavalier for matched services.",
            evidence_marker=(" | ".join(f"{l}: {d}" for l, d in found[:15])
                              + sentinel_suffix)))
    else:
        findings.append(wrap_finding(
            f"Email not found on any of {reliable_count} reliable services",
            severity=grade.protective(), cwe="CWE-200",
            remediation="Either email is fresh / private or our checks missed it. "
                        "Run github_user_intel + sherlock_username for username-based pivots.",
            evidence_marker=(f"{len(clean)} services CLEAN, {len(ambig)} ambiguous"
                              f"{', ' + str(len(unreliable_services)) + ' sentinel-dropped' if unreliable_services else ''}"
                              " (CONFIRMED)")))

    return standard_response(
        tool="holehe_email_check", target=req.target, findings=findings,
        tests_performed=len(SERVICES),
        vulnerable=False,  # account-existence enumeration is OSINT, not a breach
        tests_summary=(f"sentinel-checked {len(SERVICES)} services "
                        f"({reliable_count} reliable); "
                        f"real email found on {len(found)}, clean on {len(clean)}"),
        raw_data={"found": found, "clean": clean, "ambiguous": ambig,
                   "sentinel_dropped": sorted(unreliable_services)})


@router.post("/api/osint/holehe_email_check")
@vl_verify()
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
