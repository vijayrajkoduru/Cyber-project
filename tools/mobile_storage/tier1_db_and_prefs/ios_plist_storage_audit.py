"""ios_plist_storage_audit — for IPA files, scan Info.plist + bundled plists
for sensitive key entries (apiKey, secret, token, password) stored as
plain strings, plus UIBackgroundModes / FileProvider entries that may
leak data."""
from __future__ import annotations
import plistlib
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.ios_plist_storage_audit_findings import IOS_PLIST_STORAGE_AUDIT_FINDING_RULES

router = APIRouter()

SENSITIVE_HINTS = ("token", "password", "passwd", "secret", "apikey",
                    "api_key", "credential", "private_key", "client_secret",
                    "session", "jwt", "auth", "pin", "otp")
SCAN_MAX_FILES = 80


def _walk_plist(obj, sensitive_hits, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = str(k).lower()
            if any(h in kl for h in SENSITIVE_HINTS):
                # value type check — strings are most suspicious
                if isinstance(v, (str, bytes)) and v:
                    sensitive_hits.append({"key": str(k), "path": path,
                                            "preview": str(v)[:40]})
            _walk_plist(v, sensitive_hits, f"{path}/{k}")
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _walk_plist(item, sensitive_hits, f"{path}[{i}]")


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["ios_plist_storage_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["ios_plist_storage_audit_error"] = str(e)
        return

    sensitive_hits = []
    plists_scanned = 0
    for p in list(unpacked.rglob("*.plist"))[:SCAN_MAX_FILES]:
        try:
            with p.open("rb") as f:
                data = plistlib.load(f)
        except Exception:
            continue
        plists_scanned += 1
        _walk_plist(data, sensitive_hits, p.name)
        if len(sensitive_hits) >= 30:
            break

    if plists_scanned == 0:
        ctx.state["ios_plist_storage_audit_total"] = 0
        ctx.source("no plist files - probably not an IPA")
        return

    ctx.state["plists_scanned"] = plists_scanned
    ctx.state["sensitive_plist_hits"] = sensitive_hits
    ctx.state["ios_plist_storage_audit_total"] = len(sensitive_hits)
    ctx.source(f"{plists_scanned} plist files")


INTEL_FIELDS = [
    ("Plists scanned", "plists_scanned"),
    ("Sensitive plist hits", "sensitive_plist_hits"),
]


@router.post("/api/mobile_storage/ios_plist_storage_audit")
async def mobile_storage_ios_plist_storage_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="ios_plist_storage_audit",
        gather_func=gather,
        finding_rules=IOS_PLIST_STORAGE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
