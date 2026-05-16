"""recon_subdomain_takeover -- isolated tool (Kali-style architecture).

Route: /api/recon/subdomain_takeover
Split from recon_module.py monolith by scripts/split_recon_module.py.
Failure here is quarantined by the healing autoloader -- other tools unaffected.
"""

import asyncio
import base64
import datetime
import hashlib
import re
import socket
from typing import Optional
import requests
import dns.resolver
import dns.asyncresolver
import whois as whois_lib
from fastapi import APIRouter, Depends
from tools._shared import (
    ScanRequest, verify_scan_quota, recon_host, safe_get, web_url,
)
import aiohttp as _aiohttp_crawl
import ssl as _ssl_mod

from fastapi import APIRouter, Depends

router = APIRouter()

_TAKEOVER_SIGS = [
    ("github.io",                "There isn't a GitHub Pages site here",   "CRITICAL", "GitHub Pages"),
    ("s3.amazonaws.com",         "NoSuchBucket",                            "CRITICAL", "AWS S3"),
    ("herokuapp.com",            "No such app",                             "CRITICAL", "Heroku"),
    ("bitbucket.io",             "Repository not found",                    "CRITICAL", "Bitbucket"),
    ("tumblr.com",               "Whatever you were looking for",           "CRITICAL", "Tumblr"),
    ("wordpress.com",            "Do you want to register",                 "CRITICAL", "WordPress"),
    ("surge.sh",                 "project not found",                       "CRITICAL", "Surge.sh"),
    ("myshopify.com",            "Sorry, this shop is currently unavailable", "CRITICAL", "Shopify"),
    ("fastly.net",               "Fastly error: unknown domain",            "CRITICAL", "Fastly"),
    ("ghost.io",                 "The thing you were looking for is no longer here", "CRITICAL", "Ghost"),
    ("helpscoutdocs.com",        "No settings were found for this company", "CRITICAL", "Help Scout"),
    ("readme.io",                "Project doesnt exist",                    "CRITICAL", "Readme.io"),
    ("pingdom.com",              "Public Report Not Activated",             "HIGH",     "Pingdom"),
    ("getresponse.com",          "Unrecognized domain",                     "HIGH",     "GetResponse"),
    ("teamwork.com",             "Oops - We didn't find your site",         "HIGH",     "Teamwork"),
    ("wpengine.com",             "The site you were looking for",           "HIGH",     "WPEngine"),
    ("cargo.site",               "404 Not Found",                           "HIGH",     "Cargo"),
    ("strikinglydns.com",        "PAGE NOT FOUND",                          "HIGH",     "Strikingly"),
    ("tilda.ws",                 "Please renew your subscription",          "HIGH",     "Tilda"),
    ("uberflip.com",             "Non-Hub domain",                          "HIGH",     "Uberflip"),
    ("ngrok.io",                 "Tunnel .* not found",                     "HIGH",     "Ngrok"),
    ("pantheonsite.io",          "The gods are wise",                       "HIGH",     "Pantheon"),
    ("cloudfront.net",           "Bad request",                             "MEDIUM",   "CloudFront"),
    ("elasticbeanstalk.com",     "404 Not Found",                           "MEDIUM",   "Elastic Beanstalk"),
    ("azurewebsites.net",        "404 Web Site not found",                  "MEDIUM",   "Azure WebSites"),
    ("agilecrm.com",             "Sorry, this page is no longer available",  "HIGH",     "Agile CRM"),
    ("activecampaign.com",       "Trying to access your account",             "HIGH",     "ActiveCampaign"),
    ("acquia-sites.com",         "The site you are looking for could not be found", "HIGH", "Acquia"),
    ("aftership.com",            "Oops.</h2><p class=\"text-muted text-tight\">The page you're looking for doesn't exist", "HIGH", "AfterShip"),
    ("animaapp.io",              "Oops, this page may have been moved or deleted", "MEDIUM", "Anima"),
    ("apigee.net",               "404 Not Found",                              "MEDIUM",   "Apigee"),
    ("aws.amazon.com/apprunner", "The page you are looking for cannot be found", "HIGH",   "AWS App Runner"),
    ("bigcartel.com",            "Oops! We couldn't find that page",          "HIGH",     "Big Cartel"),
    ("brightcove.net",           "Brightcove Error",                          "MEDIUM",   "Brightcove"),
    ("campaignmonitor.com",      "Double check the URL or",                   "HIGH",     "Campaign Monitor"),
    ("canny.io",                 "Company Not Found",                         "HIGH",     "Canny"),
    ("createsend.com",           "Domain has been disabled by the administrator", "HIGH", "Campaign Monitor (sendgrid)"),
    ("desk.com",                 "Sorry, We Couldn't Find That Page",         "HIGH",     "Desk"),
    ("flywheelsites.com",        "We're sorry, you've landed on a page that is hosted by Flywheel", "HIGH", "Flywheel"),
    ("freshdesk.com",            "May be this is still fresh!",               "HIGH",     "Freshdesk"),
    ("hatena.ne.jp",             "404 Blog is not found",                     "HIGH",     "Hatena Blog"),
    ("intercom.help",            "This page is reserved for artistic use",    "HIGH",     "Intercom"),
    ("kinsta.com",               "No Site For Domain",                        "HIGH",     "Kinsta"),
    ("launchrock.com",           "It looks like you may have taken a wrong turn",  "HIGH",  "LaunchRock"),
    ("mashery.com",              "Unrecognized domain",                       "HIGH",     "Mashery"),
    ("netlify.app",              "Not Found - Request ID:",                   "HIGH",     "Netlify"),
    ("ngrok.io",                 "Tunnel .* not found",                       "HIGH",     "Ngrok"),
    ("smartling.com",            "Domain is not configured",                  "HIGH",     "Smartling"),
    ("surveysparrow.com",        "Account not found",                         "HIGH",     "SurveySparrow"),
    ("thinkific.com",            "You may have mistyped the address",         "HIGH",     "Thinkific"),
    ("unbouncepages.com",        "The requested URL was not found on this server", "HIGH","Unbounce"),
    ("vend.com",                 "Looks like you've traveled too far into cyberspace", "HIGH", "Vend"),
    ("vercel.app",               "404: NOT_FOUND",                            "HIGH",     "Vercel"),
    ("webflow.io",               "The page you are looking for doesn't exist",  "HIGH",   "Webflow"),
    ("worksites.net",            "Hello! Sorry, but the webpage you requested",  "HIGH",  "Worksites"),
    ("zendesk.com",              "Help Center Closed",                        "HIGH",     "Zendesk"),
]

async def _check_takeover(subdomain):
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        try:
            ans = await resolver.resolve(subdomain, "CNAME")
            cname = str(ans[0].target).rstrip(".").lower()
        except Exception:
            return None
        for pattern, fp, severity, service in _TAKEOVER_SIGS:
            if pattern in cname:
                try:
                    r = requests.get(
                        f"http://{subdomain}", timeout=8, allow_redirects=True,
                        headers={"User-Agent": "VulnusLab/1.0"},
                    )
                    body = (r.text or "")[:5000]
                    if fp.lower() in body.lower() or re.search(fp, body, re.I):
                        return {
                            "subdomain": subdomain, "cname": cname,
                            "service": service, "severity": severity,
                            "fingerprint": fp, "status_code": r.status_code,
                        }
                except Exception:
                    pass
        return None
    except Exception:
        return None

@router.post("/api/recon/subdomain_takeover")
async def recon_subdomain_takeover(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    all_subs = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{host}&output=json", timeout=15,
                         headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code == 200:
            for entry in r.json():
                for line in str(entry.get("name_value", "")).split("\n"):
                    line = line.strip().lower().lstrip("*.")
                    if line and line.endswith(host) and not line.startswith("*"):
                        all_subs.add(line)
    except Exception:
        pass
    all_subs.add(host)
    subs_to_check = sorted(all_subs)[:150]
    if not subs_to_check:
        return {"ok": True, "vulnerable": [], "checked": 0,
                "skipped_reason": "No subdomains discovered",
                "engine": "pure-Python (CNAME + HTTP fingerprint)"}
    results = await asyncio.gather(*[_check_takeover(s) for s in subs_to_check])
    vulnerable = [v for v in results if v is not None]
    return {
        "ok": True, "vulnerable": vulnerable,
        "total_vulnerable": len(vulnerable), "checked": len(subs_to_check),
        "services_checked": len(_TAKEOVER_SIGS),
        "engine": f"pure-Python (CNAME + HTTP fingerprint, {len(_TAKEOVER_SIGS)} services)",
    }


def register(app):
    app.include_router(router)
