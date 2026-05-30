"""content_provider_audit — exposed ContentProvider analysis.

ContentProviders without grant-uri-permission can leak data to any installed
app. Flag providers where exported=true and no read/write permission is
declared. MASVS-PLATFORM-2 / MSTG-PLATFORM-2.
"""
from pathlib import Path
from xml.etree import ElementTree as ET
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.content_provider_audit_findings import \
    CONTENT_PROVIDER_AUDIT_FINDING_RULES

router = APIRouter()
NS_A = "{http://schemas.android.com/apk/res/android}"


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["content_provider_audit_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["content_provider_audit_error"] = str(e); return

    manifest = unpacked / "AndroidManifest.xml"
    if not manifest.is_file():
        ctx.state["content_provider_audit_total"] = 0
        ctx.source("not-android"); return

    try:
        root = ET.parse(str(manifest)).getroot()
    except ET.ParseError:
        ctx.state["content_provider_audit_error"] = "manifest-not-parseable"; return

    app = root.find("application")
    providers = []
    risky = []
    if app is not None:
        for p in app.findall("provider"):
            name = p.get(f"{NS_A}name") or "?"
            authority = p.get(f"{NS_A}authorities") or "?"
            exported = p.get(f"{NS_A}exported")
            grant_uri = p.get(f"{NS_A}grantUriPermissions") == "true"
            perm = p.get(f"{NS_A}permission")
            read_perm = p.get(f"{NS_A}readPermission")
            write_perm = p.get(f"{NS_A}writePermission")
            entry = {"name": name, "authority": authority,
                      "exported": exported, "grant_uri": grant_uri,
                      "perm": perm, "read_perm": read_perm, "write_perm": write_perm}
            providers.append(entry)
            # Risky: exported=true (or default-true pre-Android 17) without any perm
            if exported == "true" and not (perm or read_perm or write_perm):
                risky.append(entry)

    ctx.state["all_providers"] = providers
    ctx.state["risky_providers"] = risky
    ctx.state["content_provider_audit_total"] = len(risky)
    ctx.source(f"{len(providers)} providers in manifest, {len(risky)} risky")


INTEL_FIELDS = [
    ("Risky exported providers", "content_provider_audit_total"),
    ("Total providers",          "all_providers"),
]


@router.post("/api/mobile_static/content_provider_audit")
async def mobile_static_content_provider_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="content_provider_audit",
        gather_func=gather,
        finding_rules=CONTENT_PROVIDER_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
