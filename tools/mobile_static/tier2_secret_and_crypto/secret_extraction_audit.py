"""secret_extraction_audit — find hardcoded secrets in decompiled tree."""
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.secret_extraction_audit_findings import SECRET_EXTRACTION_AUDIT_FINDING_RULES

router = APIRouter()

# Standard secret-detection regexes (subset of trufflehog/apkleaks rules)
PATTERNS = {
    "AWS Access Key":    re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    "AWS Secret":        re.compile(r"(?i)aws.{0,20}?(secret|access).{0,5}['\"]([A-Za-z0-9/+=]{40})['\"]"),
    "Google API Key":    re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "Firebase URL":      re.compile(r"https?://[\w.-]+\.firebaseio\.com"),
    "Stripe Live Key":   re.compile(r"\b(sk|pk)_live_[0-9a-zA-Z]{24,}\b"),
    "GitHub Token":      re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"),
    "Slack Token":       re.compile(r"\bxox[bpoars]-[0-9]{10,}-[0-9a-zA-Z]{20,}\b"),
    "JWT":               re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "RSA Private Key":   re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----"),
    "Generic API Token": re.compile(r"(?i)(api[_-]?key|api[_-]?token|access[_-]?token)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]"),
}

# Files to scan (resource + decompiled source)
SCAN_EXTS = (".java", ".kt", ".smali", ".xml", ".json", ".properties", ".yml", ".yaml")


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["secret_extraction_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["secret_extraction_audit_error"] = str(e)
        return

    hits = []
    files_scanned = 0
    for f in unpacked.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix.lower() not in SCAN_EXTS:
            continue
        # Cap at 2000 files to bound scan time
        if files_scanned >= 2000:
            break
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        files_scanned += 1
        for kind, pat in PATTERNS.items():
            for m in pat.finditer(text):
                snippet = (m.group(0)[:60] + "...") if len(m.group(0)) > 60 else m.group(0)
                hits.append({
                    "kind": kind,
                    "file": str(f.relative_to(unpacked))[:120],
                    "snippet": snippet,
                })
                if len(hits) >= 200:  # hard cap
                    break
            if len(hits) >= 200:
                break
        if len(hits) >= 200:
            break

    ctx.state["secrets_found"] = hits
    ctx.state["secret_extraction_audit_total"] = len(hits)
    ctx.state["files_scanned"] = files_scanned
    ctx.source(f"regex-scan ({files_scanned} files)")


INTEL_FIELDS = [
    ("Secrets found", "secret_extraction_audit_total"),
    ("Files scanned", "files_scanned"),
]


@router.post("/api/mobile_static/secret_extraction_audit")
async def mobile_static_secret_extraction_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="secret_extraction_audit",
        gather_func=gather,
        finding_rules=SECRET_EXTRACTION_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
