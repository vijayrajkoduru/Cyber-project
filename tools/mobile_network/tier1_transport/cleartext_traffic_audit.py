"""cleartext_traffic_audit - usesCleartextTraffic / NSAllowsArbitraryLoads.
Android: AndroidManifest application@android:usesCleartextTraffic=true OR
no NetworkSecurityConfig blocking it. iOS: NSAppTransportSecurity ->
NSAllowsArbitraryLoads=true. MSTG-NETWORK-1."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.cleartext_traffic_audit_findings import CLEARTEXT_TRAFFIC_AUDIT_FINDING_RULES

router = APIRouter()
ANDROID_CLEARTEXT_RE = re.compile(r'usesCleartextTraffic\s*=\s*"true"|cleartextTrafficPermitted\s*=\s*"true"')
ANDROID_BLOCK_RE = re.compile(r'cleartextTrafficPermitted\s*=\s*"false"|usesCleartextTraffic\s*=\s*"false"')
IOS_ATS_RE = re.compile(r'NSAllowsArbitraryLoads\s*</key>\s*<true|NSAllowsArbitraryLoads\s*=\s*true', re.IGNORECASE)
IOS_ATS_DOMAIN_RE = re.compile(r'NSExceptionDomains|NSExceptionAllowsInsecureHTTPLoads\s*</key>\s*<true', re.IGNORECASE)
# presence != usage: usesCleartextTraffic / NSAllowsArbitraryLoads are policy
# *flags* (Android <28 defaults them to true). Only grade HIGH if there is
# evidence the app actually performs cleartext HTTP — a real http:// endpoint
# URL or a plaintext-HTTP API. Exclude schema/namespace/localhost/example URLs.
HTTP_URL_RE = re.compile(r'http://[A-Za-z0-9.\-]+', re.IGNORECASE)
HTTP_IGNORE_RE = re.compile(
    r'http://(localhost|127\.0\.0\.1|10\.|0\.0\.0\.0|schemas\.|www\.w3\.org|'
    r'xmlns|ns\.adobe|apache\.org|example\.|java\.sun\.com|android\.com|'
    r'goo\.gl/|developer\.android)', re.IGNORECASE)
HTTP_CLIENT_RE = re.compile(r'HttpURLConnection|openConnection\s*\(|new\s+URL\s*\(\s*"http://')
SCAN_MAX_FILES = 2000
CODE_SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["cleartext_traffic_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["cleartext_traffic_audit_error"] = str(e); return
    android_cleartext_true = False
    android_cleartext_false = False
    ios_ats_open = False
    ios_ats_exceptions = []
    manifests, plists = [], []
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".xml", ".plist"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if p.suffix == ".xml":
            if "AndroidManifest" in p.name or "network_security_config" in p.name.lower():
                manifests.append(p.name)
                if ANDROID_CLEARTEXT_RE.search(txt): android_cleartext_true = True
                if ANDROID_BLOCK_RE.search(txt): android_cleartext_false = True
        elif p.suffix == ".plist":
            plists.append(p.name)
            if IOS_ATS_RE.search(txt): ios_ats_open = True
            if IOS_ATS_DOMAIN_RE.search(txt) and len(ios_ats_exceptions) < 10:
                ios_ats_exceptions.append(p.name)

    # Second pass: look for evidence the app *uses* cleartext HTTP — a real
    # http:// host or a plaintext HTTP client call. Without this, the flag is
    # just a permissive default and not an exploitable defect.
    http_evidence = []
    http_client_evidence = []
    code_scanned = 0
    for p in unpacked.rglob("*"):
        if code_scanned >= CODE_SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".swift", ".m", ".h", ".java", ".json", ".js"):
            continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        code_scanned += 1
        if len(http_evidence) < 10:
            for m in HTTP_URL_RE.finditer(txt):
                url = m.group(0)
                if HTTP_IGNORE_RE.match(url):
                    continue
                if url not in http_evidence:
                    http_evidence.append(url)
                if len(http_evidence) >= 10:
                    break
        if HTTP_CLIENT_RE.search(txt) and len(http_client_evidence) < 10:
            http_client_evidence.append(p.name)

    has_http_use = bool(http_evidence or http_client_evidence)
    findings_total = 0
    # Only count toward graded total when the permissive flag co-occurs with
    # actual cleartext use; the rules downgrade flag-only cases to INFO.
    if android_cleartext_true and not android_cleartext_false and has_http_use:
        findings_total += 1
    if ios_ats_open and has_http_use:
        findings_total += 1
    elif ios_ats_exceptions and has_http_use:
        findings_total += 1
    ctx.state["android_cleartext_allowed"] = android_cleartext_true
    ctx.state["android_cleartext_blocked"] = android_cleartext_false
    ctx.state["ios_ats_arbitrary_loads"] = ios_ats_open
    ctx.state["ios_ats_exception_domains"] = ios_ats_exceptions
    ctx.state["http_url_evidence"] = http_evidence
    ctx.state["http_client_evidence"] = http_client_evidence
    ctx.state["cleartext_use_confirmed"] = has_http_use
    ctx.state["files_scanned"] = files_scanned
    ctx.state["cleartext_traffic_audit_total"] = findings_total
    ctx.source(f"{files_scanned} xml/plist + {code_scanned} code")


INTEL_FIELDS = [("Android cleartext allowed", "android_cleartext_allowed"),
                ("Android cleartext blocked", "android_cleartext_blocked"),
                ("iOS NSAllowsArbitraryLoads", "ios_ats_arbitrary_loads"),
                ("iOS NSException domains", "ios_ats_exception_domains"),
                ("Cleartext HTTP URLs (evidence)", "http_url_evidence"),
                ("Plaintext HTTP client sites", "http_client_evidence")]


@router.post("/api/mobile_network/cleartext_traffic_audit")
async def mobile_network_cleartext_traffic_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="cleartext_traffic_audit",
        gather_func=gather, finding_rules=CLEARTEXT_TRAFFIC_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
