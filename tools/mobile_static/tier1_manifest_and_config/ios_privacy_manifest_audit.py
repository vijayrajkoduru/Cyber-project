"""ios_privacy_manifest_audit — Apple PrivacyInfo.xcprivacy required-reason audit."""
import plistlib
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.ios_privacy_manifest_audit_findings import (
    IOS_PRIVACY_MANIFEST_AUDIT_FINDING_RULES,
)

router = APIRouter()

APPROVED_API_REASONS = {
    "NSPrivacyAccessedAPICategoryFileTimestamp": {"C617.1", "DDA9.1", "0A2A.1", "3B52.1"},
    "NSPrivacyAccessedAPICategorySystemBootTime": {"35F9.1", "8FFB.1", "3D61.1"},
    "NSPrivacyAccessedAPICategoryDiskSpace": {"E174.1", "85F4.1", "7D9E.1", "B728.1"},
    "NSPrivacyAccessedAPICategoryActiveKeyboards": {"3EC4.1", "54BD.1"},
    "NSPrivacyAccessedAPICategoryUserDefaults": {"CA92.1", "1C8F.1", "C56D.1", "AC6B.1"},
}


def _find_xcprivacy(root):
    return list(root.rglob("PrivacyInfo.xcprivacy"))


def _find_info_plist(root):
    for p in root.rglob("Info.plist"):
        if "/Payload/" in str(p).replace("\\", "/") and p.parent.suffix == ".app":
            return p
    for p in root.rglob("Info.plist"):
        return p
    return None


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["ios_privacy_manifest_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["ios_privacy_manifest_audit_error"] = str(e)
        return

    info = _find_info_plist(unpacked)
    if info is None:
        ctx.state["ios_privacy_manifest_audit_total"] = 0
        ctx.source("not-ios-bundle")
        return

    files = _find_xcprivacy(unpacked)
    if not files:
        ctx.state["xcprivacy_missing"] = True
        ctx.state["ios_privacy_manifest_audit_total"] = 1
        ctx.source("no-PrivacyInfo.xcprivacy")
        return

    issues = []
    for p in files[:10]:
        try:
            with p.open("rb") as f:
                data = plistlib.load(f)
        except Exception:
            issues.append({"file": p.name, "issue": "not-parseable"})
            continue

        if bool(data.get("NSPrivacyTracking")) and not (data.get("NSPrivacyTrackingDomains") or []):
            issues.append({"file": p.name, "issue": "tracking-true-but-empty-domains"})

        if data.get("NSPrivacyCollectedDataTypes") is None:
            issues.append({"file": p.name, "issue": "NSPrivacyCollectedDataTypes-missing"})

        for entry in (data.get("NSPrivacyAccessedAPITypes") or []):
            cat = entry.get("NSPrivacyAccessedAPIType") or ""
            reasons = entry.get("NSPrivacyAccessedAPITypeReasons") or []
            approved = APPROVED_API_REASONS.get(cat)
            if approved is None:
                continue
            bad = [r for r in reasons if r not in approved]
            if bad:
                issues.append({"file": p.name, "issue": "bad-required-reason",
                               "category": cat, "codes": ",".join(bad[:3])})
            if not reasons:
                issues.append({"file": p.name, "issue": "empty-required-reason", "category": cat})

    ctx.state["privacy_issues"] = issues
    ctx.state["ios_privacy_manifest_audit_total"] = len(issues)
    ctx.source("PrivacyInfo.xcprivacy")


INTEL_FIELDS = [("iOS Privacy Manifest issues", "ios_privacy_manifest_audit_total")]


@router.post("/api/mobile_static/ios_privacy_manifest_audit")
async def mobile_static_ios_privacy_manifest_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="ios_privacy_manifest_audit",
        gather_func=gather,
        finding_rules=IOS_PRIVACY_MANIFEST_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
