"""backup_extraction_audit — extends §1 manifest audit with backup-policy depth.
Checks: android:allowBackup, android:fullBackupContent, the backup_rules.xml
file's include/exclude tags, dataExtractionRules (Android 12+), and
android:fullBackupOnly. An app handling money/PII should set
allowBackup=false OR ship a strict include/exclude policy."""
from __future__ import annotations
from pathlib import Path
from xml.etree import ElementTree as ET

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.backup_extraction_audit_findings import BACKUP_EXTRACTION_AUDIT_FINDING_RULES

router = APIRouter()

NS = {"a": "http://schemas.android.com/apk/res/android"}


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["backup_extraction_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["backup_extraction_audit_error"] = str(e)
        return

    manifest = unpacked / "AndroidManifest.xml"
    if not manifest.is_file():
        ctx.state["backup_extraction_audit_total"] = 0
        ctx.source("no-manifest")
        return

    try:
        root = ET.parse(str(manifest)).getroot()
    except ET.ParseError:
        ctx.state["backup_extraction_audit_error"] = "manifest-not-parseable"
        return

    app = root.find("application")
    allow_backup = None
    full_backup_content = None
    data_extraction_rules = None
    full_backup_only = None
    if app is not None:
        allow_backup = app.get(f"{{{NS['a']}}}allowBackup")
        full_backup_content = app.get(f"{{{NS['a']}}}fullBackupContent")
        data_extraction_rules = app.get(f"{{{NS['a']}}}dataExtractionRules")
        full_backup_only = app.get(f"{{{NS['a']}}}fullBackupOnly")

    # Look for backup_rules.xml content if referenced
    backup_rules_summary = None
    rules_file = None
    if full_backup_content and full_backup_content.startswith("@xml/"):
        rules_path = full_backup_content[5:]
        for cand in (unpacked / "res" / "xml").glob(f"{rules_path}.xml"):
            try:
                rules_xml = ET.parse(str(cand)).getroot()
                includes = [e.get("path") for e in rules_xml.findall(".//include")]
                excludes = [e.get("path") for e in rules_xml.findall(".//exclude")]
                backup_rules_summary = {"includes": [x for x in includes if x][:20],
                                          "excludes": [x for x in excludes if x][:20]}
                rules_file = cand.name
                break
            except ET.ParseError:
                pass

    findings_total = 0
    if allow_backup == "true":
        findings_total += 1
    if allow_backup == "true" and not full_backup_content and not data_extraction_rules:
        findings_total += 1  # truly open backups

    ctx.state["allow_backup"] = allow_backup
    ctx.state["full_backup_content"] = full_backup_content
    ctx.state["data_extraction_rules"] = data_extraction_rules
    ctx.state["full_backup_only"] = full_backup_only
    ctx.state["backup_rules_file"] = rules_file
    ctx.state["backup_rules_summary"] = backup_rules_summary
    ctx.state["backup_extraction_audit_total"] = findings_total
    ctx.source("AndroidManifest.xml + backup rules xml")


INTEL_FIELDS = [
    ("android:allowBackup", "allow_backup"),
    ("fullBackupContent ref", "full_backup_content"),
    ("dataExtractionRules ref (Android 12+)", "data_extraction_rules"),
    ("Backup rules summary", "backup_rules_summary"),
]


@router.post("/api/mobile_storage/backup_extraction_audit")
async def mobile_storage_backup_extraction_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="backup_extraction_audit",
        gather_func=gather,
        finding_rules=BACKUP_EXTRACTION_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
