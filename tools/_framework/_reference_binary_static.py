"""Reference binary-static scanner — NOT a real scanner.

This file shows the EXACT shape every binary-static scanner should follow.
The vl_foundry.py forge loads it as the in-context example when generating
new binary-static scanners (the analog of recon/wayback.py for passive mode).

DO NOT register this with the autoloader — it's a template, not a tool.
"""
import subprocess
from pathlib import Path
from xml.etree import ElementTree as ET

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.apk_cache import get_unpacked
# from tools._payloads._reference_binary_static_findings import REFERENCE_FINDING_RULES

router = APIRouter()


async def gather(ctx: ScanContext):
    """Read uploaded APK (ctx.host), populate ctx.state with findings.

    Pattern:
      1. Validate file exists
      2. Get unpacked dir via apk_cache (shared, isolated)
      3. Run analysis (subprocess OR pure-Python parse)
      4. Populate ctx.state[*] keys + ctx.source(*)
    """
    apk_path = ctx.host
    if not Path(apk_path).is_file():
        ctx.state["reference_total"] = 0
        ctx.source("file-not-found")
        return

    try:
        unpacked = get_unpacked(apk_path)
    except Exception as e:
        ctx.state["reference_error"] = str(e)
        return

    # Example A — pure-Python parse of AndroidManifest.xml (after apktool decode)
    manifest = unpacked / "AndroidManifest.xml"
    findings = []
    if manifest.is_file():
        try:
            tree = ET.parse(str(manifest))
            root = tree.getroot()
            app = root.find("application")
            if app is not None:
                ns = "{http://schemas.android.com/apk/res/android}"
                if app.get(f"{ns}debuggable") == "true":
                    findings.append({"flag": "debuggable",
                                     "evidence": "AndroidManifest.xml application@android:debuggable=true"})
                if app.get(f"{ns}allowBackup") == "true":
                    findings.append({"flag": "allowBackup",
                                     "evidence": "AndroidManifest.xml application@android:allowBackup=true"})
            ctx.source("manifest-xml-parse")
        except ET.ParseError:
            pass  # silent — autoloader will see no source registered

    # Example B — subprocess to a CLI tool (checksec)
    libs_dir = unpacked / "lib"
    if libs_dir.is_dir():
        for so in list(libs_dir.rglob("*.so"))[:10]:  # cap at 10 libs
            try:
                r = subprocess.run(["checksec", "--file=" + str(so), "--format=json"],
                                   capture_output=True, text=True, timeout=10)
                if r.returncode == 0:
                    ctx.source("checksec")
                    # Parse r.stdout JSON, append to findings
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                continue

    ctx.state["reference_total"] = len(findings)
    ctx.state["reference_findings_raw"] = findings


# What to render in the report
INTEL_FIELDS = [
    ("Manifest issues", "reference_total"),
]


@router.post("/api/reference/reference_scanner")
async def reference_reference_scanner(req: ScanRequest, _=Depends(verify_scan_quota)):
    # For binary-static: req.target IS the uploaded apk_path
    apk_path = req.target
    return await run_scanner(
        host=apk_path, tool="reference_scanner",
        gather_func=gather,
        finding_rules=[],  # would be REFERENCE_FINDING_RULES
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


# Required at EOF — autoloader looks for this:
def register(app):
    # Intentionally a no-op for the reference file — this is a template,
    # not a real scanner.
    pass
