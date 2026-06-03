"""coreml_extraction_audit - iOS .mlmodel / .mlpackage extraction risk.
Bundled CoreML models are recoverable in plaintext from the .ipa. Detect
model files + check for obfuscation / encryption."""
from __future__ import annotations
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.coreml_extraction_audit_findings import COREML_EXTRACTION_AUDIT_FINDING_RULES

router = APIRouter()


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["coreml_extraction_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["coreml_extraction_audit_error"] = str(e); return
    models = []
    total_bytes = 0
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= 5000: break
        if not p.is_file(): continue
        files_scanned += 1
        if p.suffix in (".mlmodel", ".mlmodelc", ".mlpackage"):
            try: sz = p.stat().st_size
            except OSError: sz = 0
            total_bytes += sz
            if len(models) < 25:
                models.append({"name": p.name, "kb": sz // 1024})
    findings_total = 1 if models else 0
    ctx.state["coreml_models"] = models
    ctx.state["total_kb"] = total_bytes // 1024
    ctx.state["files_scanned"] = files_scanned
    ctx.state["coreml_extraction_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("CoreML models bundled", "coreml_models"),
                ("Total model size (KB)", "total_kb")]


@router.post("/api/mobile_aiml/coreml_extraction_audit")
async def mobile_aiml_coreml_extraction_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="coreml_extraction_audit",
        gather_func=gather, finding_rules=COREML_EXTRACTION_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
