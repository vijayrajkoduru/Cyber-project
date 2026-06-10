"""tflite_extraction_audit - Android .tflite / .pb model extraction risk.
Bundled TensorFlow Lite models are extractable via `apktool d`. Detect
files + size + obfuscation patterns."""
from __future__ import annotations
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.tflite_extraction_audit_findings import TFLITE_EXTRACTION_AUDIT_FINDING_RULES

router = APIRouter()


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["tflite_extraction_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["tflite_extraction_audit_error"] = str(e); return
    models = []
    total_bytes = 0
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= 5000: break
        if not p.is_file(): continue
        files_scanned += 1
        if p.suffix in (".tflite", ".pb", ".onnx", ".pt"):
            try: sz = p.stat().st_size
            except OSError: sz = 0
            total_bytes += sz
            if len(models) < 25:
                models.append({"name": p.name, "ext": p.suffix, "kb": sz // 1024})
    findings_total = 1 if models else 0
    ctx.state["ml_models"] = models
    ctx.state["total_kb"] = total_bytes // 1024
    ctx.state["files_scanned"] = files_scanned
    ctx.state["tflite_extraction_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("ML models bundled", "ml_models"),
                ("Total model size (KB)", "total_kb")]


@router.post("/api/mobile_aiml/tflite_extraction_audit")
async def mobile_aiml_tflite_extraction_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="tflite_extraction_audit",
        gather_func=gather, finding_rules=TFLITE_EXTRACTION_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
