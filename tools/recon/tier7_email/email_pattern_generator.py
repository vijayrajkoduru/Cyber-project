"""Email Pattern Generator — Route: /api/recon/email_pattern_generator
Generates likely employee email addresses from email_patterns.txt + target domain.
Intel-only (no SMTP probing) — pairs with hunter_io / holehe for validation."""
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner

router = APIRouter()
_PAYLOAD = Path(__file__).resolve().parent.parent.parent / "_payloads" / "recon" / "email_patterns.txt"

def _load():
    try:
        if _PAYLOAD.exists():
            return [l.strip() for l in _PAYLOAD.read_text(encoding="utf-8").splitlines()
                    if l.strip() and not l.startswith("#")]
    except Exception: pass
    return ["{first}.{last}@{domain}","{first}@{domain}","{f}{last}@{domain}",
            "{first}{last}@{domain}","{last}.{first}@{domain}"]

_SAMPLE_NAMES = [("john","doe"),("jane","smith"),("admin","admin"),
                 ("info","info"),("contact","contact"),("hello","hello")]

async def gather(ctx: ScanContext):
    domain = ctx.host
    patterns = _load()
    ctx.state["patterns_count"] = len(patterns)
    ctx.source("pattern-list")
    candidates = set()
    for p in patterns:
        for first, last in _SAMPLE_NAMES:
            email = p.replace("{first}", first).replace("{last}", last) \
                     .replace("{f}", first[0]).replace("{l}", last[0]) \
                     .replace("{domain}", domain)
            candidates.add(email.lower())
    candidates = sorted(candidates)
    ctx.state["candidates"] = candidates
    ctx.state["candidates_count"] = len(candidates)
    ctx.source(f"generated ({len(candidates)})")

def r_generated(s):
    c = s.get("candidates") or []
    if not c: return None
    return {"name": f"Email candidates generated for OSINT ({len(c)})",
            "severity": "INFO",
            "evidence": f"Sample: {', '.join(c[:6])}",
            "remediation": "Feed candidates into hunter.io / holehe / SMTP validation for confirmation. Train staff on phishing — your email pattern is predictable."}

def r_empty(s):
    if s.get("candidates"): return None
    return {"name":"No email candidates generated","severity":"INFO",
            "evidence":"Pattern list empty or domain invalid."}

FINDING_RULES = [r_generated, r_empty]
INTEL_FIELDS = [("Patterns loaded","patterns_count"),("Candidates generated","candidates_count")]

@router.post("/api/recon/email_pattern_generator")
async def recon_email_pattern_generator(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="email_pattern_generator",
        gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS,
        flat_field_keys=["candidates","candidates_count"])

def register(app): app.include_router(router)
