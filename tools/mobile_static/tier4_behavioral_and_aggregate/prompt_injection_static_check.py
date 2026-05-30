"""prompt_injection_static_check — code patterns where user input feeds LLM call. ⭐ 2025+

OWASP LLM Top 10 #1: prompt injection. If your app concatenates user
text into a system/user prompt without sanitization, attacker can hijack
your LLM. Scans DEX for the dangerous pattern:
  - user-input source (EditText.getText / TextField / clipboard)
  - flowing INTO an LLM API call (openai.com / anthropic.com / generateContent)

This is a HEURISTIC static check — false negatives possible (intermediate
variables). Pairs with runtime fuzz testing in mobile_runtime module.

MASVS-CODE-3 emerging. NEW 2025+.
"""
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.prompt_injection_static_check_findings import \
    PROMPT_INJECTION_STATIC_CHECK_FINDING_RULES

router = APIRouter()

LLM_CALL_MARKERS = [
    b"api.openai.com", b"chat/completions",
    b"api.anthropic.com", b"v1/messages",
    b"generativelanguage.googleapis.com", b"generateContent",
    b"api.groq.com", b"api.together.xyz",
    b"openai.ChatCompletion", b"anthropic.messages",
    b"OpenAIApi", b"AnthropicClient",
]

USER_INPUT_MARKERS = [
    b"EditText", b"getText()",                 # Android
    b"UITextField", b"UITextView",             # iOS Swift/ObjC
    b"TextField", b"TextEditor",                # SwiftUI
    b"WebView", b"loadUrl",
    b"ClipboardManager", b"UIPasteboard",
    b"Intent.getStringExtra",
    b"BufferedReader", b"BufferedInputStream",
]


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["prompt_injection_static_check_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["prompt_injection_static_check_error"] = str(e); return

    llm_files = []  # files that contain LLM API call markers
    input_in_llm_file = []  # subset that ALSO contain user-input markers
    files_scanned = 0
    for f in unpacked.rglob("*"):
        if not f.is_file(): continue
        if f.suffix not in (".dex", ".smali") and "classes" not in f.name: continue
        try:
            data = f.read_bytes()[:10_000_000]
        except Exception: continue
        files_scanned += 1
        has_llm = any(m in data for m in LLM_CALL_MARKERS)
        if not has_llm: continue
        llm_files.append(f.relative_to(unpacked).as_posix())
        has_user_input = any(m in data for m in USER_INPUT_MARKERS)
        if has_user_input:
            input_in_llm_file.append(f.relative_to(unpacked).as_posix())

    ctx.state["llm_call_files"]  = llm_files
    ctx.state["input_in_llm_file"] = input_in_llm_file
    ctx.state["prompt_injection_static_check_total"] = len(input_in_llm_file)
    ctx.state["files_scanned"] = files_scanned
    ctx.source(f"scanned {files_scanned}, LLM={len(llm_files)}, "
                f"input+LLM={len(input_in_llm_file)}")


INTEL_FIELDS = [
    ("LLM-API files",          "llm_call_files"),
    ("LLM+user-input files",   "input_in_llm_file"),
    ("Files scanned",          "files_scanned"),
]


@router.post("/api/mobile_static/prompt_injection_static_check")
async def mobile_static_prompt_injection_static_check(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="prompt_injection_static_check",
        gather_func=gather,
        finding_rules=PROMPT_INJECTION_STATIC_CHECK_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
