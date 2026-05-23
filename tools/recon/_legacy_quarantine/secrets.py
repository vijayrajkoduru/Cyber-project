"""recon_secrets -- isolated tool (Kali-style architecture).

Route: /api/recon/secrets
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

_SECRET_PATTERNS = [
    ("AWS Access Key",        r"AKIA[0-9A-Z]{16}"),
    ("AWS Session Token",     r"FQoG[A-Za-z0-9/+=]{50,}"),
    ("AWS Secret (in JS)",    r"(?i)aws(.{0,20})?(secret|priv|key)?(.{0,20})?[\"\'][0-9a-zA-Z/+]{40}[\"\']"),
    ("Google API Key",        r"AIza[0-9A-Za-z_-]{35}"),
    ("Google OAuth",          r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    ("Google Cloud Service Account", r"\"type\":\s*\"service_account\""),
    ("Firebase URL",          r"[a-z0-9.-]+\.firebaseio\.com"),
    ("Slack Token",           r"xox[baprs]-[0-9a-zA-Z]{10,}"),
    ("Slack Webhook",         r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ("GitHub PAT (classic)",  r"ghp_[0-9A-Za-z]{36}"),
    ("GitHub PAT (fine)",     r"github_pat_[0-9A-Za-z_]{82}"),
    ("GitHub OAuth",          r"gho_[0-9A-Za-z]{36}"),
    ("GitHub App Token",      r"(ghu|ghs)_[0-9A-Za-z]{36}"),
    ("GitHub Refresh",        r"ghr_[0-9A-Za-z]{76}"),
    ("GitLab PAT",            r"glpat-[0-9a-zA-Z_-]{20}"),
    ("Bitbucket Client ID",   r"(?i)bitbucket(.{0,20})?[\"\'][0-9a-zA-Z]{32}[\"\']"),
    ("Stripe Live Secret",    r"sk_live_[0-9a-zA-Z]{24,}"),
    ("Stripe Restricted",     r"rk_live_[0-9a-zA-Z]{24,}"),
    ("Stripe Publishable",    r"pk_live_[0-9a-zA-Z]{24,}"),
    ("PayPal Braintree",      r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
    ("Square OAuth",          r"sq0atp-[0-9A-Za-z-_]{22}"),
    ("Square Access Token",   r"sq0csp-[0-9A-Za-z-_]{43}"),
    ("Mailgun API",           r"key-[0-9a-zA-Z]{32}"),
    ("Mailchimp API",         r"[0-9a-f]{32}-us[0-9]{1,2}"),
    ("SendGrid API",          r"SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}"),
    ("Twilio Account SID",    r"AC[a-z0-9]{32}"),
    ("Twilio API Key SID",    r"SK[a-z0-9]{32}"),
    ("Heroku API",            r"(?i)heroku.{0,20}?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"),
    ("Dropbox Long Token",    r"sl\.[A-Za-z0-9_-]{135,}"),
    ("Dropbox API",           r"(?i)dropbox.{0,20}?[a-z0-9]{15}"),
    ("Discord Bot Token",     r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}"),
    ("Discord Webhook",       r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"),
    ("OpenAI API Key",        r"sk-[A-Za-z0-9]{48}"),
    ("OpenAI Project Key",    r"sk-proj-[A-Za-z0-9_-]{40,}"),
    ("Anthropic API Key",     r"sk-ant-[A-Za-z0-9-_]{90,}"),
    ("Hugging Face Token",    r"hf_[A-Za-z0-9]{30,}"),
    ("RSA Private Key",       r"-----BEGIN RSA PRIVATE KEY-----"),
    ("SSH Private Key",       r"-----BEGIN (OPENSSH|DSA|EC|PGP) PRIVATE KEY-----"),
    ("PKCS8 Private Key",     r"-----BEGIN PRIVATE KEY-----"),
    ("Encrypted Private Key", r"-----BEGIN ENCRYPTED PRIVATE KEY-----"),
    ("Certificate",           r"-----BEGIN CERTIFICATE-----"),
    ("JWT Token",             r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
    ("Basic Auth in URL",     r"https?://[^/\s:@]+:[^/\s:@]{4,}@[^/\s]+"),
    ("MongoDB URI",           r"mongodb(\+srv)?://[^/\s:@]+:[^/\s:@]+@[^/\s]+"),
    ("MySQL URI",             r"mysql://[^/\s:@]+:[^/\s:@]+@[^/\s]+"),
    ("PostgreSQL URI",        r"postgres(ql)?://[^/\s:@]+:[^/\s:@]+@[^/\s]+"),
    ("Redis URI w/ pass",     r"redis://[^/\s:@]+:[^/\s:@]+@[^/\s]+"),
    ("Datadog API Key",       r"(?i)datadog.{0,20}?[a-z0-9]{32}"),
    ("New Relic API Key",     r"NRAK-[A-Z0-9]{27}"),
    ("PagerDuty Service",     r"pdus[+_]?[0-9a-zA-Z]{32}"),
    ("Splunk Token",          r"splunk_[a-zA-Z0-9]{32}"),
    ("Atlassian API Token",   r"(?i)atlassian.{0,20}?[a-z0-9]{24}"),
    ("Algolia API Key",       r"(?i)algolia.{0,20}?[a-zA-Z0-9]{32}"),
    ("Cloudflare API Key",    r"(?i)cloudflare.{0,20}?[a-f0-9]{37}"),
    ("Cloudflare API Token",  r"(?i)cloudflare.{0,20}?[A-Za-z0-9_]{40,}"),
    ("Vercel Token",          r"(?i)vercel.{0,20}?[A-Za-z0-9]{24}"),
    ("Netlify Token",         r"(?i)netlify.{0,20}?[A-Za-z0-9_-]{38}"),
    ("npm Token",             r"npm_[A-Za-z0-9]{36}"),
    ("PyPI Token",            r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]+"),
    ("Sentry DSN w/ secret",  r"https://[a-f0-9]+:[a-f0-9]+@[a-z0-9-]+\.ingest\.sentry\.io"),
    ("Asana Token",           r"(?i)asana.{0,20}?[0-9]/[0-9]{16,}:[a-z0-9]{32}"),
    ("Linear API Key",        r"lin_api_[A-Za-z0-9]{40}"),
    ("Notion API Token",      r"secret_[A-Za-z0-9]{43}"),
    ("Airtable API Key",      r"key[A-Za-z0-9]{14}"),
    ("Airtable PAT",          r"pat[A-Za-z0-9]{14}\.[a-f0-9]{64}"),
    ("Shopify API Token",     r"shpat_[a-f0-9]{32}"),
    ("Shopify Custom App",    r"shpca_[a-f0-9]{32}"),
    ("Shopify Shared Secret", r"shpss_[a-f0-9]{32}"),
    ("WordPress API Key",     r"(?i)wp-api.{0,20}?[a-zA-Z0-9]{32}"),
    ("CircleCI Token",        r"(?i)circle-token.{0,5}[a-f0-9]{40}"),
    ("Buildkite API",         r"(?i)buildkite.{0,20}?[a-z0-9]{40}"),
    ("Snyk API Key",          r"(?i)snyk.{0,20}?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    ("Postman API Key",       r"PMAK-[a-f0-9]{24}-[a-f0-9]{34}"),
    ("Telegram Bot Token",    r"[0-9]{8,10}:AA[A-Za-z0-9_-]{33}"),
    ("Adafruit IO Key",       r"(?i)adafruit.{0,20}?[a-z0-9]{32}"),
    ("DigitalOcean PAT",      r"dop_v1_[a-f0-9]{64}"),
    ("Linode API Token",      r"(?i)linode.{0,20}?[a-f0-9]{64}"),
    ("Hetzner API Token",     r"(?i)hcloud.{0,20}?[a-zA-Z0-9]{64}"),
    ("AWS Secret Key",       r"(?i)aws(.{0,20})?(secret|priv)?(.{0,20})?[\"\'][0-9a-zA-Z/+]{40}[\"\']"),
    ("Google API Key",       r"AIza[0-9A-Za-z_-]{35}"),
    ("Google OAuth",         r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    ("Slack Token",          r"xox[baprs]-[0-9a-zA-Z]{10,}"),
    ("Slack Webhook",        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ("GitHub PAT (classic)", r"ghp_[0-9A-Za-z]{36}"),
    ("GitHub PAT (fine)",    r"github_pat_[0-9A-Za-z_]{82}"),
    ("GitHub OAuth",         r"gho_[0-9A-Za-z]{36}"),
    ("GitHub App Token",     r"(ghu|ghs)_[0-9A-Za-z]{36}"),
    ("Stripe Live",          r"sk_live_[0-9a-zA-Z]{24,}"),
    ("Stripe Restricted",    r"rk_live_[0-9a-zA-Z]{24,}"),
    ("Stripe Publishable",   r"pk_live_[0-9a-zA-Z]{24,}"),
    ("Mailgun API",          r"key-[0-9a-zA-Z]{32}"),
    ("SendGrid API",         r"SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}"),
    ("Twilio Account SID",   r"AC[a-z0-9]{32}"),
    ("Twilio API Key",       r"SK[a-z0-9]{32}"),
    ("Heroku API",           r"(?i)heroku.{0,20}?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"),
    ("Dropbox API",          r"sl\.[A-Za-z0-9_-]{135,}"),
    ("Discord Bot Token",    r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}"),
    ("Discord Webhook",      r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"),
    ("OpenAI API Key",       r"sk-[A-Za-z0-9]{48}"),
    ("Anthropic API Key",    r"sk-ant-[A-Za-z0-9-_]{90,}"),
    ("Square OAuth",         r"sq0atp-[0-9A-Za-z-_]{22}"),
    ("RSA Private Key",      r"-----BEGIN RSA PRIVATE KEY-----"),
    ("SSH Private Key",      r"-----BEGIN (OPENSSH|DSA|EC|PGP) PRIVATE KEY-----"),
    ("JWT Token",            r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
    ("Basic Auth in URL",    r"https?://[^/\s:@]+:[^/\s:@]{4,}@[^/\s]+"),
]

@router.post("/api/recon/secrets")
async def recon_secrets(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    r = safe_get(base, req=req, allow_redirects=True)
    if r is None:
        return {"ok": False, "secrets": [], "skipped_reason": f"Could not reach {base}"}
    js_urls = re.findall(r'src=["\']([^"\']+\.js)', r.text)
    secrets, js_count = [], 0
    for js_url in js_urls[:5]:
        full = js_url if js_url.startswith("http") else f"{base}/{js_url.lstrip('/')}"
        rjs = safe_get(full, req=req)
        if rjs is None:
            continue
        js_count += 1
        for name, pattern in _SECRET_PATTERNS:
            for m in re.finditer(pattern, rjs.text):
                secrets.append({"type": name, "match": m.group(0)[:60], "file": full})
    return {"ok": True, "secrets": secrets, "js_files": js_count}


def register(app):
    app.include_router(router)
