"""ondevice_llm_audit - On-device LLM (Mistral / Phi / Gemma / Llama) detection.
Multi-GB models bundled in-app or downloaded post-install. Detect ggml /
gguf / safetensors signatures + llama.cpp / mlc-llm SDK references."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.ondevice_llm_audit_findings import ONDEVICE_LLM_AUDIT_FINDING_RULES

router = APIRouter()
LLM_SDK_RE = re.compile(r'llama\.cpp|mlc-llm|MLCEngine|ggml|llama\.swift|MediaPipeTasks|tensorflow-lite-task-text')
MODEL_EXT = {".gguf", ".ggml", ".safetensors", ".bin"}
LARGE_MODEL_THRESHOLD = 100 * 1024 * 1024  # 100 MB


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["ondevice_llm_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["ondevice_llm_audit_error"] = str(e); return
    sdk_users = []
    large_models = []
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= 5000: break
        if not p.is_file(): continue
        files_scanned += 1
        if p.suffix in MODEL_EXT:
            try: sz = p.stat().st_size
            except OSError: sz = 0
            if sz >= LARGE_MODEL_THRESHOLD and len(large_models) < 10:
                large_models.append({"name": p.name, "mb": sz // (1024 * 1024)})
        if p.suffix in (".smali", ".swift", ".m", ".java"):
            try: txt = p.read_text(errors="ignore")
            except (OSError, UnicodeDecodeError): continue
            if LLM_SDK_RE.search(txt) and len(sdk_users) < 20:
                sdk_users.append(p.name)
    findings_total = 0
    if large_models: findings_total += 1
    if sdk_users: findings_total += 1
    ctx.state["llm_sdk_users"] = sdk_users
    ctx.state["large_models"] = large_models
    ctx.state["files_scanned"] = files_scanned
    ctx.state["ondevice_llm_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("LLM SDK references", "llm_sdk_users"),
                ("Large models (>100MB)", "large_models")]


@router.post("/api/mobile_aiml/ondevice_llm_audit")
async def mobile_aiml_ondevice_llm_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="ondevice_llm_audit",
        gather_func=gather, finding_rules=ONDEVICE_LLM_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
