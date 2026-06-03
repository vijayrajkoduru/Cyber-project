"""iap_replay_audit - IAP receipt replay protection.
Detect: nonce / transactionId persistence + dedup logic + timestamp
freshness checks. Catches the classic "use one receipt N times" abuse."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.iap_replay_audit_findings import IAP_REPLAY_AUDIT_FINDING_RULES

router = APIRouter()
TRANSACTION_ID_RE = re.compile(r'transactionIdentifier|getOriginalJson|orderId|transactionDate')
DEDUP_LOGIC_RE = re.compile(r'alreadyConsumed|hasBeenAcknowledged|previousTransactionId|isReplay')
NONCE_RE = re.compile(r'appAccountToken|jws.*nonce|requestNonce')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["iap_replay_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["iap_replay_audit_error"] = str(e); return
    tx_users, dedup_users, nonce_users = [], [], []
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".swift", ".m", ".java"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if TRANSACTION_ID_RE.search(txt) and len(tx_users) < 20: tx_users.append(p.name)
        if DEDUP_LOGIC_RE.search(txt) and len(dedup_users) < 20: dedup_users.append(p.name)
        if NONCE_RE.search(txt) and len(nonce_users) < 20: nonce_users.append(p.name)
    findings_total = 0
    if tx_users and not dedup_users and not nonce_users: findings_total += 1
    ctx.state["transaction_id_users"] = tx_users
    ctx.state["dedup_logic_users"] = dedup_users
    ctx.state["nonce_users"] = nonce_users
    ctx.state["files_scanned"] = files_scanned
    ctx.state["iap_replay_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("transactionId users", "transaction_id_users"),
                ("Dedup-logic users", "dedup_logic_users"),
                ("Nonce users", "nonce_users")]


@router.post("/api/mobile_payment/iap_replay_audit")
async def mobile_payment_iap_replay_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="iap_replay_audit",
        gather_func=gather, finding_rules=IAP_REPLAY_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
