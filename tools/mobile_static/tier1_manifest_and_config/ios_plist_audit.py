"""ios_plist_audit — Info.plist + entitlements audit for IPA."""
import plistlib
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.ios_plist_audit_findings import IOS_PLIST_AUDIT_FINDING_RULES

router = APIRouter()


def _find_plists(root: Path):
    """Find Info.plist + .entitlements files inside Payload/<app>.app/."""
    out = []
    for p in root.rglob("*.plist"):
        try:
            if p.name == "Info.plist" or "/Payload/" in str(p):
                out.append(p)
        except Exception:
            continue
    for p in root.rglob("*.entitlements"):
        out.append(p)
    return out


def _load_plist(p: Path):
    try:
        with p.open("rb") as f:
            return plistlib.load(f)
    except Exception:
        return None


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["ios_plist_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["ios_plist_audit_error"] = str(e)
        return

    plists = _find_plists(unpacked)
    if not plists:
        ctx.state["ios_plist_audit_total"] = 0
        ctx.source("no-plist")
        return

    issues = []
    for p in plists[:10]:
        data = _load_plist(p)
        if not data:
            continue
        ats = data.get("NSAppTransportSecurity") or {}
        if ats.get("NSAllowsArbitraryLoads") is True:
            issues.append({"flag": "NSAllowsArbitraryLoads",
                           "file": p.name,
                           "value": "true"})
        # ATS exceptions per-domain
        for dom, conf in (ats.get("NSExceptionDomains") or {}).items():
            if (conf or {}).get("NSExceptionAllowsInsecureHTTPLoads") is True:
                issues.append({"flag": "NSExceptionAllowsInsecureHTTPLoads",
                               "file": p.name, "domain": dom})
        # File-sharing exposes Documents folder via iTunes/Files
        if data.get("UIFileSharingEnabled") is True:
            issues.append({"flag": "UIFileSharingEnabled",
                           "file": p.name, "value": "true"})
        # Debug entitlement that shouldn't ship in release
        if data.get("com.apple.security.get-task-allow") is True:
            issues.append({"flag": "get-task-allow",
                           "file": p.name, "value": "true"})

    ctx.state["plist_issues"] = issues
    ctx.state["ios_plist_audit_total"] = len(issues)
    ctx.source("plistlib")


INTEL_FIELDS = [
    ("iOS plist issues", "ios_plist_audit_total"),
]


@router.post("/api/mobile_static/ios_plist_audit")
async def mobile_static_ios_plist_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="ios_plist_audit",
        gather_func=gather,
        finding_rules=IOS_PLIST_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
