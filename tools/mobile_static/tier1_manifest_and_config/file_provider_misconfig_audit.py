"""file_provider_misconfig_audit — FileProvider grant-uri wildcard + exported audit."""
from pathlib import Path
from xml.etree import ElementTree as ET

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.file_provider_misconfig_audit_findings import (
    FILE_PROVIDER_MISCONFIG_AUDIT_FINDING_RULES,
)

router = APIRouter()

NS = {"a": "http://schemas.android.com/apk/res/android"}
PATH_TAGS = ("root-path", "files-path", "cache-path", "external-path",
             "external-files-path", "external-cache-path",
             "external-media-path")


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["file_provider_misconfig_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["file_provider_misconfig_audit_error"] = str(e)
        return

    manifest = unpacked / "AndroidManifest.xml"
    if not manifest.is_file():
        ctx.state["file_provider_misconfig_audit_total"] = 0
        ctx.source("no-manifest")
        return

    try:
        root = ET.parse(str(manifest)).getroot()
    except ET.ParseError:
        ctx.state["file_provider_misconfig_audit_error"] = "manifest-not-parseable"
        return

    app = root.find("application")
    if app is None:
        ctx.state["file_provider_misconfig_audit_total"] = 0
        ctx.source("no-application")
        return

    fp_exported = []
    fp_with_grant = []

    for prov in app.findall("provider"):
        name = prov.get(f"{{{NS['a']}}}name") or "?"
        if "fileprovider" not in name.lower():
            continue
        if prov.get(f"{{{NS['a']}}}exported") == "true":
            fp_exported.append(name)
        if prov.get(f"{{{NS['a']}}}grantUriPermissions") == "true":
            fp_with_grant.append({"name": name})

    wildcards = []
    res_xml = unpacked / "res" / "xml"
    if res_xml.is_dir():
        for xml_file in res_xml.glob("*.xml"):
            try:
                sub = ET.parse(str(xml_file)).getroot()
            except ET.ParseError:
                continue
            if sub.tag != "paths":
                continue
            for child in sub.iter():
                tag = child.tag.lower()
                if tag not in PATH_TAGS:
                    continue
                path_val = (child.get("path") or child.get(f"{{{NS['a']}}}path") or "").strip()
                if path_val in ("", "/", "."):
                    wildcards.append({
                        "file": xml_file.name,
                        "element": tag,
                        "path": path_val or "(empty)",
                    })

    ctx.state["fp_exported"] = fp_exported
    ctx.state["fp_with_grant"] = fp_with_grant
    ctx.state["fp_wildcards"] = wildcards
    ctx.state["file_provider_misconfig_audit_total"] = len(fp_exported) + len(wildcards)
    ctx.source("AndroidManifest.xml + res/xml/")


INTEL_FIELDS = [("FileProvider misconfigs", "file_provider_misconfig_audit_total")]


@router.post("/api/mobile_static/file_provider_misconfig_audit")
async def mobile_static_file_provider_misconfig_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="file_provider_misconfig_audit",
        gather_func=gather,
        finding_rules=FILE_PROVIDER_MISCONFIG_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
