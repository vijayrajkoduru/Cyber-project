"""ai_ml_model_detection — detect bundled AI/ML model files. ⭐ 2025+

Mobile apps are increasingly shipping local LLMs / vision models / on-device
inference. These can leak via: (a) model file extraction → competitor IP
theft, (b) prompt injection against bundled small-LLM, (c) model tampering
to influence app behavior. MASVS-CODE-3 emerging guidance.

Detects: TFLite, CoreML, ONNX, PyTorch, GGUF (llama.cpp), ML Kit assets.
"""
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.ai_ml_model_detection_findings import \
    AI_ML_MODEL_DETECTION_FINDING_RULES

router = APIRouter()

MODEL_EXTENSIONS = {
    ".tflite":   "TensorFlow Lite",
    ".mlmodel":  "Apple Core ML",
    ".mlmodelc": "Apple Core ML (compiled)",
    ".mlpackage":"Apple Core ML package",
    ".onnx":     "ONNX",
    ".pt":       "PyTorch state dict",
    ".pth":      "PyTorch (legacy)",
    ".gguf":     "GGUF (llama.cpp-compatible)",
    ".ggml":     "GGML (legacy)",
    ".safetensors": "SafeTensors",
    ".bin":      "Generic binary (may be model)",
    ".pb":       "TensorFlow protobuf",
    ".h5":       "Keras H5",
    ".trt":      "TensorRT engine",
}

# DEX markers for ML SDK use
SDK_MARKERS = [
    (b"Lcom/google/mlkit/",          "Google ML Kit"),
    (b"Lcom/google/firebase/ml/",    "Firebase ML"),
    (b"Lorg/tensorflow/lite/",       "TensorFlow Lite"),
    (b"Lai/onnxruntime/",            "ONNX Runtime"),
    (b"LlamaContext",                "llama.cpp wrapper"),
    (b"CoreML.framework",            "CoreML"),
    (b"VisionKit",                   "Apple VisionKit"),
]


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["ai_ml_model_detection_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["ai_ml_model_detection_error"] = str(e); return

    models = []
    sdks = []
    sdk_files_scanned = 0

    # 1. Find model files by extension
    for f in unpacked.rglob("*"):
        if not f.is_file(): continue
        ext = f.suffix.lower()
        if ext in MODEL_EXTENSIONS:
            try:
                size = f.stat().st_size
            except Exception:
                size = 0
            # .bin is overloaded — only count >1MB ones as candidate models
            if ext == ".bin" and size < 1_000_000:
                continue
            models.append({"path": f.relative_to(unpacked).as_posix(),
                            "format": MODEL_EXTENSIONS[ext],
                            "size_mb": round(size / 1024 / 1024, 2)})

    # 2. Find SDK references in DEX
    for f in unpacked.rglob("*"):
        if not f.is_file(): continue
        if f.suffix not in (".dex", ".smali") and "classes" not in f.name: continue
        try:
            data = f.read_bytes()[:10_000_000]
        except Exception: continue
        sdk_files_scanned += 1
        for marker, name in SDK_MARKERS:
            if marker in data and name not in [s["name"] for s in sdks]:
                sdks.append({"name": name, "marker": marker.decode(errors="ignore")})

    ctx.state["models_found"] = models
    ctx.state["ai_sdks_found"] = sdks
    ctx.state["ai_ml_model_detection_total"] = len(models) + len(sdks)
    ctx.state["sdk_files_scanned"] = sdk_files_scanned
    ctx.source(f"{len(models)} model file(s), {len(sdks)} AI SDK(s)")


INTEL_FIELDS = [
    ("Bundled model files", "models_found"),
    ("AI/ML SDKs detected", "ai_sdks_found"),
    ("DEX files scanned",   "sdk_files_scanned"),
]


@router.post("/api/mobile_static/ai_ml_model_detection")
async def mobile_static_ai_ml_model_detection(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="ai_ml_model_detection",
        gather_func=gather,
        finding_rules=AI_ML_MODEL_DETECTION_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
