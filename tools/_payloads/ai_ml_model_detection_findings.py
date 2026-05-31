"""ai_ml_model_detection — findings rules."""


def rule_positive_emit(s):
    n = s.get("ai_ml_model_detection_total", 0)
    if n > 0: return None
    return {"name": "No AI/ML models or SDKs detected in bundle",
            "severity": "POSITIVE",
            "cwe": "CWE-200", "owasp": "M9:2023",
            "evidence": f"scanned {s.get('sdk_files_scanned', 0)} files, no models/SDKs",
            "remediation": "App doesn't ship on-device ML — no model-extraction / "
                           "prompt-injection / model-tamper risk surface."}


def rule_large_model_bundled(s):
    models = s.get("models_found") or []
    big = [m for m in models if m.get("size_mb", 0) >= 50]
    if not big: return None
    return {"name": f"LARGE on-device model(s) bundled ({len(big)} >= 50MB)",
            "severity": "MEDIUM", "cvss": "5.0",
            "cwe": "CWE-200", "owasp": "M9:2023",
            "evidence": " | ".join(f"{m['path']} ({m['size_mb']}MB, {m['format']})" for m in big[:5]),
            "remediation": "Large models (esp. .gguf, .safetensors, .pt) often represent "
                           "valuable trained IP. Anyone can extract these from the APK/IPA. "
                           "If proprietary: (1) consider server-side inference instead, "
                           "(2) if must be on-device: encrypt-at-rest + decrypt-in-memory "
                           "with Android Keystore / iOS Secure Enclave-derived key. "
                           "(3) Watermark model weights (model-watermarking research)."}


def rule_models_inventory(s):
    models = s.get("models_found") or []
    if not models: return None
    return {"name": f"AI/ML models bundled ({len(models)})",
            "severity": "INFO",
            "cwe": "CWE-200", "owasp": "M9:2023",
            "evidence": " | ".join(f"{m['path']} ({m['format']}, {m['size_mb']}MB)" for m in models[:8]),
            "remediation": "Document on-device ML in privacy policy. Most users assume "
                           "their data is sent to cloud — on-device ML still processes "
                           "personal data even if it doesn't leave the device. Apple App "
                           "Privacy + Play Data Safety forms require accurate disclosure."}


def rule_ai_sdk_inventory(s):
    sdks = s.get("ai_sdks_found") or []
    if not sdks: return None
    return {"name": f"AI/ML SDK(s) integrated ({len(sdks)})",
            "severity": "INFO",
            "cwe": "CWE-1395", "owasp": "M9:2023",
            "evidence": " | ".join(s_["name"] for s_ in sdks),
            "remediation": "ML Kit / TFLite / ONNX-Runtime SDKs each have their own "
                           "CVE history. Subscribe to their security advisories. "
                           "For on-device LLM apps: implement prompt-injection defense "
                           "(separator tokens, OWASP LLM Top 10 #1)."}


AI_ML_MODEL_DETECTION_FINDING_RULES = [
    rule_positive_emit,
    rule_large_model_bundled,
    rule_models_inventory,
    rule_ai_sdk_inventory,
]
