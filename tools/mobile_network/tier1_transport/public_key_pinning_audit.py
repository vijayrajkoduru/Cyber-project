"""public_key_pinning_audit - PKP / HPKP-style pinning in NetworkSecurityConfig
+ iOS App Transport Security pins. Complements cert_pinning_static (which
detects code-level pinning). MSTG-NETWORK-4."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.public_key_pinning_audit_findings import PUBLIC_KEY_PINNING_AUDIT_FINDING_RULES

router = APIRouter()
NSC_PIN_RE = re.compile(r'<pin-set[^>]*>|<pin\s+digest="', re.IGNORECASE)
NSC_BACKUP_PIN_RE = re.compile(r'<pin\s+digest="SHA-256">[^<]+</pin>\s*<pin\s+digest="SHA-256">[^<]+</pin>', re.DOTALL)
IOS_ATS_PIN_RE = re.compile(r'NSPinnedDomains|NSPinnedCAIdentities|NSPinnedLeafIdentities', re.IGNORECASE)
SCAN_MAX_FILES = 2000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["public_key_pinning_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["public_key_pinning_audit_error"] = str(e); return
    nsc_pinning_files = []
    nsc_has_backup = False
    ios_pin_files = []
    has_nsc = False
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".xml", ".plist"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if p.suffix == ".xml" and "network_security_config" in p.name.lower():
            has_nsc = True
            if NSC_PIN_RE.search(txt):
                if len(nsc_pinning_files) < 20:
                    nsc_pinning_files.append(p.name)
                if NSC_BACKUP_PIN_RE.search(txt):
                    nsc_has_backup = True
        elif p.suffix == ".plist":
            if IOS_ATS_PIN_RE.search(txt) and len(ios_pin_files) < 20:
                ios_pin_files.append(p.name)
    findings_total = 0
    if nsc_pinning_files and not nsc_has_backup:
        findings_total += 1
    if has_nsc and not nsc_pinning_files and not ios_pin_files:
        findings_total += 1
    ctx.state["nsc_pinning_files"] = nsc_pinning_files
    ctx.state["nsc_has_backup_pin"] = nsc_has_backup
    ctx.state["ios_pin_files"] = ios_pin_files
    ctx.state["has_network_security_config"] = has_nsc
    ctx.state["files_scanned"] = files_scanned
    ctx.state["public_key_pinning_audit_total"] = findings_total
    ctx.source(f"{files_scanned} xml/plist")


INTEL_FIELDS = [("NSC pinning files", "nsc_pinning_files"),
                ("NSC has backup pin", "nsc_has_backup_pin"),
                ("iOS NSPinnedDomains", "ios_pin_files"),
                ("Has network_security_config", "has_network_security_config")]


@router.post("/api/mobile_network/public_key_pinning_audit")
async def mobile_network_public_key_pinning_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="public_key_pinning_audit",
        gather_func=gather, finding_rules=PUBLIC_KEY_PINNING_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
