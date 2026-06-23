"""android_manifest_audit — parse AndroidManifest.xml for risky flags."""
from pathlib import Path
from xml.etree import ElementTree as ET

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.android_manifest_audit_findings import ANDROID_MANIFEST_AUDIT_FINDING_RULES
from tools._payloads.mobile._fp_gates import is_sdk_component, is_sensitive_component

router = APIRouter()

NS = {"a": "http://schemas.android.com/apk/res/android"}


def _attr(el, name):
    return el.get(f"{{{NS['a']}}}{name}")


def _to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["android_manifest_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["android_manifest_audit_error"] = str(e)
        return

    manifest = unpacked / "AndroidManifest.xml"
    if not manifest.is_file():
        ctx.state["android_manifest_audit_total"] = 0
        ctx.source("no-manifest")
        return

    try:
        root = ET.parse(str(manifest)).getroot()
    except ET.ParseError:
        ctx.state["android_manifest_audit_error"] = "manifest-not-parseable"
        return

    # SDK levels for default-behaviour context (allowBackup default flips at 31).
    uses_sdk = root.find("uses-sdk")
    min_sdk = _to_int(_attr(uses_sdk, "minSdkVersion")) if uses_sdk is not None else None
    target_sdk = _to_int(_attr(uses_sdk, "targetSdkVersion")) if uses_sdk is not None else None

    app = root.find("application")
    findings_total = 0
    if app is not None:
        # debuggable: only a finding if EXPLICITLY true (default is false).
        if _attr(app, "debuggable") == "true":
            ctx.state["debuggable"] = True
            findings_total += 1

        # allowBackup: default is true pre-API-31. Flag only when explicitly
        # enabled AND no backup-restriction rules limit what gets backed up.
        # If the dev scoped backups (fullBackupContent / dataExtractionRules) the
        # risk is mitigated -> INFO/context, not a graded MEDIUM.
        allow_backup_attr = _attr(app, "allowBackup")
        has_backup_rules = bool(_attr(app, "fullBackupContent") or
                                _attr(app, "dataExtractionRules"))
        if allow_backup_attr == "true":
            ctx.state["allow_backup"] = True
            ctx.state["allow_backup_explicit"] = True
            ctx.state["allow_backup_scoped"] = has_backup_rules
            if not has_backup_rules:
                findings_total += 1
        elif allow_backup_attr is None and (min_sdk is None or min_sdk < 31):
            # Relying on the pre-31 default (true) — context only, not graded.
            ctx.state["allow_backup"] = True
            ctx.state["allow_backup_explicit"] = False
            ctx.state["allow_backup_scoped"] = has_backup_rules

        # Exported components: only GRADE when the component is (a) unprotected by
        # any permission, (b) NOT a known SDK component (FileProvider, Firebase,
        # Play billing, ad activities...), and (c) its name hints at a sensitive
        # surface. Other exported-without-permission components are reported INFO.
        graded_exported = []
        benign_exported = []
        for tag in ("activity", "service", "receiver", "provider", "activity-alias"):
            for el in app.findall(tag):
                name = el.get(f"{{{NS['a']}}}name") or "?"
                exp = el.get(f"{{{NS['a']}}}exported")
                if exp != "true":
                    continue
                # Component-level permission protection (incl. provider r/w perms).
                protected = bool(_attr(el, "permission") or
                                 _attr(el, "readPermission") or
                                 _attr(el, "writePermission"))
                rec = {"name": name, "type": tag}
                if protected:
                    continue
                if is_sdk_component(name):
                    rec["reason"] = "known SDK component"
                    benign_exported.append(rec)
                elif is_sensitive_component(name):
                    rec["reason"] = "sensitive name, unprotected"
                    graded_exported.append(rec)
                else:
                    rec["reason"] = "unprotected (no sensitive hint)"
                    benign_exported.append(rec)
        if graded_exported:
            ctx.state["exported_components"] = graded_exported
            findings_total += len(graded_exported)
        if benign_exported:
            ctx.state["exported_components_info"] = benign_exported

    # Permissions
    perms = [p.get(f"{{{NS['a']}}}name", "?") for p in root.findall("uses-permission")]
    dangerous = [p for p in perms if p.startswith("android.permission.") and any(
        d in p for d in ("READ_SMS", "RECEIVE_SMS", "READ_CONTACTS", "ACCESS_FINE_LOCATION",
                          "RECORD_AUDIO", "READ_CALL_LOG", "CAMERA"))]
    if dangerous:
        ctx.state["dangerous_permissions"] = dangerous
        findings_total += len(dangerous)

    ctx.state["android_manifest_audit_total"] = findings_total
    ctx.source("AndroidManifest.xml")


INTEL_FIELDS = [
    ("Risky flags + components", "android_manifest_audit_total"),
]


@router.post("/api/mobile_static/android_manifest_audit")
async def mobile_static_android_manifest_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="android_manifest_audit",
        gather_func=gather,
        finding_rules=ANDROID_MANIFEST_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
