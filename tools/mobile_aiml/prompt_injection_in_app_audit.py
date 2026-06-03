"""prompt_injection_in_app_audit - app-embedded LLM clients prompt-injection surface.

Detects OpenAI / Anthropic / Gemini / Mistral SDK usage + concatenation of
user input into system prompts without sanitization."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.prompt_injection_in_app_audit_findings import PROMPT_INJECTION_IN_APP_AUDIT_FINDING_RULES

router = APIRouter()
LLM_API_RE = re.compile(r'api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.mistral\.ai|api\.x\.ai')
SDK_RE = re.compile(r'OpenAIKit|AnthropicSDK|GoogleGenerativeAI|MistralAI|LangChain|LlamaIndex')
SYSTEM_PROMPT_RE = re.compile(r'role.*?system|systemPrompt|messages.*?system')
USER_CONCAT_RE = re.compile(r'userInput\s*\+|messages\.append\(.*userInput|f"\{userInput\}"', re.IGNORECASE)
SANITIZER_RE = re.compile(r'sanitize|escape|stripPromptInjection|llm_guard')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["prompt_injection_in_app_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["prompt_injection_in_app_audit_error"] = str(e); return
    api_users, sdk_users = [], []
    system_prompt_files = []
    user_concat_files = []
    sanitizer_uses = 0
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".swift", ".m", ".java", ".js"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if LLM_API_RE.search(txt) and len(api_users) < 20: api_users.append(p.name)
        if SDK_RE.search(txt) and len(sdk_users) < 20: sdk_users.append(p.name)
        if SYSTEM_PROMPT_RE.search(txt) and len(system_prompt_files) < 20:
            system_prompt_files.append(p.name)
        if USER_CONCAT_RE.search(txt) and len(user_concat_files) < 20:
            user_concat_files.append(p.name)
        if SANITIZER_RE.search(txt): sanitizer_uses += 1
    findings_total = 0
    if (api_users or sdk_users) and user_concat_files and sanitizer_uses == 0:
        findings_total += 1
    ctx.state["llm_api_users"] = api_users
    ctx.state["llm_sdk_users"] = sdk_users
    ctx.state["system_prompt_files"] = system_prompt_files
    ctx.state["user_concat_files"] = user_concat_files
    ctx.state["sanitizer_uses"] = sanitizer_uses
    ctx.state["files_scanned"] = files_scanned
    ctx.state["prompt_injection_in_app_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("LLM API users", "llm_api_users"),
                ("LLM SDK users", "llm_sdk_users"),
                ("System-prompt files", "system_prompt_files"),
                ("User-input concat sites", "user_concat_files"),
                ("Sanitizer uses", "sanitizer_uses")]


@router.post("/api/mobile_aiml/prompt_injection_in_app_audit")
async def mobile_aiml_prompt_injection_in_app_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="prompt_injection_in_app_audit",
        gather_func=gather, finding_rules=PROMPT_INJECTION_IN_APP_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
