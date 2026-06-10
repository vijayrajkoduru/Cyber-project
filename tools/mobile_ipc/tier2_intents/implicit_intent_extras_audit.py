"""implicit_intent_extras_audit - sensitive extras leak via implicit Intents.

`new Intent(ACTION_SEND).putExtra("password", pwd); startActivity(intent)`
broadcasts to any app that handles ACTION_SEND. Should use explicit
Intent (setComponent / setPackage) when extras contain secrets. MASVS-PLATFORM-1."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.implicit_intent_extras_audit_findings import IMPLICIT_INTENT_EXTRAS_AUDIT_FINDING_RULES

router = APIRouter()
IMPLICIT_ACTION_RE = re.compile(r'new\s+Intent\s*\(\s*"?(Intent\.)?ACTION_(?:SEND|VIEW|EDIT|PICK|GET_CONTENT)')
EXPLICIT_RE = re.compile(r'setComponent\s*\(|setPackage\s*\(|setClassName\s*\(')
PUTEXTRA_SENSITIVE_RE = re.compile(r'putExtra\s*\(\s*"([^"]+)"', re.IGNORECASE)
SENSITIVE_HINTS = ("password", "passwd", "pwd", "token", "secret", "auth",
                    "credential", "session", "api_key", "private_key", "access_token",
                    "refresh_token", "card", "cvv", "cvc", "pin", "otp")
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["implicit_intent_extras_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["implicit_intent_extras_audit_error"] = str(e); return
    leaky = []
    explicit_uses = 0
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES: break
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if EXPLICIT_RE.search(txt): explicit_uses += 1
        if IMPLICIT_ACTION_RE.search(txt) and not EXPLICIT_RE.search(txt):
            sens_extras = []
            for em in PUTEXTRA_SENSITIVE_RE.finditer(txt):
                k = em.group(1).lower()
                if any(h in k for h in SENSITIVE_HINTS):
                    sens_extras.append(em.group(1))
            if sens_extras:
                if len(leaky) < 20:
                    leaky.append({"file": p.name, "extras": sens_extras[:5]})
    findings_total = 1 if leaky else 0
    ctx.state["leaky_implicit_intents"] = leaky
    ctx.state["explicit_intent_uses"] = explicit_uses
    ctx.state["files_scanned"] = files_scanned
    ctx.state["implicit_intent_extras_audit_total"] = findings_total
    ctx.source(f"{files_scanned} smali")


INTEL_FIELDS = [("Leaky implicit intents", "leaky_implicit_intents"),
                ("Explicit intent uses", "explicit_intent_uses")]


@router.post("/api/mobile_ipc/implicit_intent_extras_audit")
async def mobile_ipc_implicit_intent_extras_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="implicit_intent_extras_audit",
        gather_func=gather, finding_rules=IMPLICIT_INTENT_EXTRAS_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
