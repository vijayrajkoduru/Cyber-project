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
# Capture both the key and (when present) the literal value of putExtra.
PUTEXTRA_KV_RE = re.compile(r'putExtra\s*\(\s*"([^"]+)"\s*,\s*("([^"]*)")?', re.IGNORECASE)
SENSITIVE_HINTS = ("password", "passwd", "pwd", "token", "secret", "auth",
                    "credential", "session", "api_key", "private_key", "access_token",
                    "refresh_token", "card", "cvv", "cvc", "pin", "otp")
# presence != usage: a key literally named "password" is weak evidence (could
# be a label / form field id). Grade only when the *value* looks like real
# sensitive data: a JWT/bearer token, an email, a PAN (card), or a long
# high-entropy secret. Key-name-only hits are downgraded to INFO.
VALUE_SENSITIVE_RES = (
    re.compile(r'\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}\.'),          # JWT
    re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),     # email
    re.compile(r'\b(?:\d[ \-]?){13,19}\b'),                                  # card PAN
    re.compile(r'\b(?:sk|pk|ghp|xox[baprs]|AKIA|AIza)[A-Za-z0-9_\-]{12,}'),  # API key prefixes
    re.compile(r'\bBearer\s+[A-Za-z0-9._\-]{12,}'),                          # bearer token
)
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["implicit_intent_extras_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["implicit_intent_extras_audit_error"] = str(e); return
    leaky = []           # confirmed: sensitive-looking VALUE in extra
    suspect = []         # key-name-only hint, value not confirmed sensitive
    explicit_uses = 0
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES: break
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if EXPLICIT_RE.search(txt): explicit_uses += 1
        if IMPLICIT_ACTION_RE.search(txt) and not EXPLICIT_RE.search(txt):
            confirmed_extras = []
            suspect_extras = []
            for em in PUTEXTRA_KV_RE.finditer(txt):
                key = em.group(1)
                val_literal = em.group(3)  # inner value, if a string literal
                key_hit = any(h in key.lower() for h in SENSITIVE_HINTS)
                # Real sensitive value: check the literal value (if any) OR a
                # short window after the putExtra for a sensitive-format token.
                window = txt[em.start():em.start() + 200]
                val_hit = bool(val_literal and any(r.search(val_literal) for r in VALUE_SENSITIVE_RES)) \
                    or any(r.search(window) for r in VALUE_SENSITIVE_RES)
                if val_hit:
                    confirmed_extras.append(key)
                elif key_hit:
                    suspect_extras.append(key)
            if confirmed_extras and len(leaky) < 20:
                leaky.append({"file": p.name, "extras": confirmed_extras[:5]})
            elif suspect_extras and len(suspect) < 20:
                suspect.append({"file": p.name, "extras": suspect_extras[:5]})
    findings_total = 1 if leaky else 0
    ctx.state["leaky_implicit_intents"] = leaky
    ctx.state["suspect_implicit_intents"] = suspect
    ctx.state["explicit_intent_uses"] = explicit_uses
    ctx.state["files_scanned"] = files_scanned
    ctx.state["implicit_intent_extras_audit_total"] = findings_total
    ctx.source(f"{files_scanned} smali")


INTEL_FIELDS = [("Leaky implicit intents", "leaky_implicit_intents"),
                ("Suspect (key-name only)", "suspect_implicit_intents"),
                ("Explicit intent uses", "explicit_intent_uses")]


@router.post("/api/mobile_ipc/implicit_intent_extras_audit")
async def mobile_ipc_implicit_intent_extras_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="implicit_intent_extras_audit",
        gather_func=gather, finding_rules=IMPLICIT_INTENT_EXTRAS_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
