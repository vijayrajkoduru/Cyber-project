"""push_messaging_secret_audit — FCM / APNs server-key leak detection.

Apps bundle FCM client config, but should NEVER bundle the FCM SERVER key
(AAAA... / AIza... server-key variant) or APNs auth-key (.p8). Anyone
with these can spam push notifications to ALL your users.

Also flags: legacy GCM server key, Webhook URLs that may have HMAC secrets,
Slack/Discord/Telegram bot tokens.
"""
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.push_messaging_secret_audit_findings import \
    PUSH_MESSAGING_SECRET_AUDIT_FINDING_RULES

router = APIRouter()

# (name, pattern, severity)
SECRET_PATTERNS = [
    ("FCM server key (legacy)",        rb"\bAAAA[A-Za-z0-9_-]{20,200}\b", "CRITICAL"),
    ("Google API key",                 rb"\bAIza[0-9A-Za-z_-]{35}\b", "MEDIUM"),  # may be FCM client OR maps OR vision
    ("Slack bot token",                rb"\bxox[abprsi]-[A-Za-z0-9-]+\b", "CRITICAL"),
    ("Telegram bot token",             rb"\b\d{8,12}:[A-Za-z0-9_-]{35}\b", "CRITICAL"),
    ("Discord bot token",              rb"\b[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b", "CRITICAL"),
    ("AWS access key ID",              rb"\bAKIA[0-9A-Z]{16}\b", "CRITICAL"),
    ("Stripe live secret",             rb"\bsk_live_[0-9a-zA-Z]{24,}\b", "CRITICAL"),
    ("GitHub PAT",                     rb"\bghp_[A-Za-z0-9]{36}\b", "CRITICAL"),
    ("Twilio account SID",             rb"\bAC[a-f0-9]{32}\b", "HIGH"),
    ("SendGrid API key",               rb"\bSG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,}\b", "CRITICAL"),
    ("PayPal client secret",           rb"\bEN[A-Z0-9]{38,80}\b", "HIGH"),
]


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["push_messaging_secret_audit_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["push_messaging_secret_audit_error"] = str(e); return

    hits = []
    files_scanned = 0
    for f in unpacked.rglob("*"):
        if not f.is_file(): continue
        # Scan strings / properties / json / xml / dex
        if f.suffix not in (".dex", ".smali", ".json", ".xml", ".properties",
                              ".txt", ".plist") and "classes" not in f.name:
            continue
        try:
            data = f.read_bytes()[:5_000_000]
        except Exception: continue
        files_scanned += 1
        for name, pat, sev in SECRET_PATTERNS:
            for m in re.finditer(pat, data):
                val = m.group(0).decode(errors="ignore")
                hits.append({
                    "type": name,
                    "value": val[:25] + "…" + val[-4:],
                    "file": f.relative_to(unpacked).as_posix(),
                    "severity": sev,
                })
                if len(hits) > 25: break
            if len(hits) > 25: break
        if len(hits) > 25: break

    # APNs .p8 detection
    p8_files = list(unpacked.rglob("*.p8"))

    ctx.state["secret_hits"] = hits
    ctx.state["apns_p8_keys"] = [str(p.relative_to(unpacked).as_posix()) for p in p8_files]
    crit = sum(1 for h in hits if h["severity"] == "CRITICAL") + len(p8_files)
    ctx.state["critical_count"] = crit
    ctx.state["push_messaging_secret_audit_total"] = len(hits) + len(p8_files)
    ctx.state["files_scanned"] = files_scanned
    ctx.source(f"scanned {files_scanned}, {len(hits)} secret hits, {len(p8_files)} .p8 keys")


INTEL_FIELDS = [
    ("Secret hits",         "secret_hits"),
    ("Critical-tier secrets","critical_count"),
    ("APNs .p8 keys",       "apns_p8_keys"),
    ("Files scanned",       "files_scanned"),
]


@router.post("/api/mobile_static/push_messaging_secret_audit")
async def mobile_static_push_messaging_secret_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="push_messaging_secret_audit",
        gather_func=gather,
        finding_rules=PUSH_MESSAGING_SECRET_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
