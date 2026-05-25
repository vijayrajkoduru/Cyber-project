"""endpoint_classifier (§5 #71 extended) — extract URLs from decompiled
code AND classify each by purpose: API / analytics / ads / internal /
debug / CDN. Helps customer prioritize MITM testing — focus Burp on the
API endpoints, ignore the analytics noise."""
from __future__ import annotations
import re
from pathlib import Path
from urllib.parse import urlparse

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.endpoint_classifier_findings import ENDPOINT_CLASSIFIER_FINDING_RULES

router = APIRouter()

URL_PATTERN = re.compile(r'"(https?://[A-Za-z0-9.\-:/%_+#?&=]{8,200})"')
CLASSIFIER_RULES = [
    ("debug",     ["localhost", "127.0.0.1", "10.0.2.2", ":8080", ":3000", "dev.", "staging.", "test.", "qa."]),
    ("internal",  [".local", ".corp", ".internal", "intranet", "192.168.", "172.16.", "172.17.", "172.18.", "172.31."]),
    ("analytics", ["google-analytics.com", "googleadservices", "amplitude", "mixpanel", "segment.io", "segment.com",
                    "branch.io", "appsflyer", "adjust.com", "kochava", "firebase-settings"]),
    ("ads",       ["doubleclick.net", "googlesyndication", "googletagmanager", "googletagservices",
                    "applovin", "ironsrc.com", "vungle.com", "unityads.unity3d.com", "facebook.com/audience_network"]),
    ("crash",     ["crashlytics", "bugsnag", "sentry.io", "rollbar.com", "raygun.io", "instabug"]),
    ("cdn",       ["cloudfront.net", "akamai", "fastly.net", "cdn.", "static.", "assets."]),
    ("api",       ["/api/", "/v1/", "/v2/", "/v3/", "api.", "/graphql", "/rest/"]),
    ("auth",      ["oauth", "/login", "/auth", "/token", ".well-known/openid", "auth0.com", "okta.com"]),
]
SCAN_MAX_FILES = 3000


def _classify(url: str) -> str:
    u = url.lower()
    for label, markers in CLASSIFIER_RULES:
        if any(m in u for m in markers):
            return label
    return "other"


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["endpoint_classifier_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["endpoint_classifier_error"] = str(e)
        return

    classified = {}      # category -> set of hostnames
    debug_endpoints = []
    files_scanned = 0
    seen_urls = set()
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1
        for m in URL_PATTERN.finditer(txt):
            url = m.group(1)
            if url in seen_urls or len(seen_urls) > 500:
                continue
            seen_urls.add(url)
            cat = _classify(url)
            host = urlparse(url).hostname or url
            classified.setdefault(cat, set()).add(host)
            if cat == "debug" and len(debug_endpoints) < 30:
                debug_endpoints.append(url)

    # Convert sets to sorted lists for JSON
    out = {k: sorted(v)[:30] for k, v in classified.items()}
    ctx.state["classified_endpoints"] = out
    ctx.state["debug_endpoints"] = debug_endpoints
    ctx.state["total_unique_urls"] = len(seen_urls)
    ctx.state["files_scanned"] = files_scanned
    ctx.state["endpoint_classifier_total"] = 1 if debug_endpoints else 0
    ctx.source(f"{files_scanned} smali files, {len(seen_urls)} unique URLs")


INTEL_FIELDS = [
    ("Endpoints by category", "classified_endpoints"),
    ("Debug / staging URLs (likely production leak)", "debug_endpoints"),
    ("Total unique URLs", "total_unique_urls"),
]


@router.post("/api/mobile_network/endpoint_classifier")
async def mobile_network_endpoint_classifier(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="endpoint_classifier",
        gather_func=gather,
        finding_rules=ENDPOINT_CLASSIFIER_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
