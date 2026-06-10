"""deeplink_verification_audit — autoVerify + intent-filter scheme audit.

Deeplink hijacking: if your app handles 'https://yourapp.com/X' via intent
filter WITHOUT android:autoVerify='true', any malicious app can also
register the same intent filter and intercept your deeplinks. Check that
all https:// intent-filters have autoVerify='true' and that the domain
hosts /.well-known/assetlinks.json. MASVS-PLATFORM-3.
"""
from pathlib import Path
from xml.etree import ElementTree as ET
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.deeplink_verification_audit_findings import \
    DEEPLINK_VERIFICATION_AUDIT_FINDING_RULES

router = APIRouter()
NS_A = "{http://schemas.android.com/apk/res/android}"


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["deeplink_verification_audit_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["deeplink_verification_audit_error"] = str(e); return

    manifest = unpacked / "AndroidManifest.xml"
    if not manifest.is_file():
        ctx.state["deeplink_verification_audit_total"] = 0
        ctx.source("not-android"); return
    try:
        root = ET.parse(str(manifest)).getroot()
    except ET.ParseError:
        ctx.state["deeplink_verification_audit_error"] = "manifest-not-parseable"; return

    deeplinks = []
    unverified = []
    custom_schemes = []
    for activity in root.findall(".//activity"):
        for intent in activity.findall("intent-filter"):
            auto_verify = intent.get(f"{NS_A}autoVerify") == "true"
            for data in intent.findall("data"):
                scheme = data.get(f"{NS_A}scheme") or ""
                host = data.get(f"{NS_A}host") or ""
                if scheme in ("http", "https") and host:
                    entry = {"scheme": scheme, "host": host,
                              "autoVerify": auto_verify,
                              "activity": activity.get(f"{NS_A}name", "?")}
                    deeplinks.append(entry)
                    if not auto_verify:
                        unverified.append(entry)
                elif scheme and scheme not in ("http", "https", "android.intent.action"):
                    custom_schemes.append({"scheme": scheme, "host": host,
                                            "activity": activity.get(f"{NS_A}name", "?")})

    ctx.state["all_deeplinks"] = deeplinks
    ctx.state["unverified_deeplinks"] = unverified
    ctx.state["custom_scheme_deeplinks"] = custom_schemes
    ctx.state["deeplink_verification_audit_total"] = (
        len(unverified) + len(custom_schemes))
    ctx.source(f"{len(deeplinks)} https deeplinks, {len(unverified)} unverified, "
                f"{len(custom_schemes)} custom-scheme")


INTEL_FIELDS = [
    ("Unverified deeplinks",     "deeplink_verification_audit_total"),
    ("HTTPS deeplinks",          "all_deeplinks"),
    ("Custom-scheme deeplinks",  "custom_scheme_deeplinks"),
]


@router.post("/api/mobile_static/deeplink_verification_audit")
async def mobile_static_deeplink_verification_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="deeplink_verification_audit",
        gather_func=gather,
        finding_rules=DEEPLINK_VERIFICATION_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
