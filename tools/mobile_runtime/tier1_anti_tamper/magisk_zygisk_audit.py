"""magisk_zygisk_audit - Magisk / Zygisk / Riru hide-tool detection.

Modern Android root frameworks (Magisk Hide, Zygisk, Riru) bypass naive
su / busybox checks. App must look for: /sbin/.magisk, /data/adb/magisk,
zygisk-hooked native libs, daemon sockets. MASVS-RESILIENCE-1."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.magisk_zygisk_audit_findings import MAGISK_ZYGISK_AUDIT_FINDING_RULES

router = APIRouter()
MAGISK_PATH_RE = re.compile(r'/sbin/\.magisk|/data/adb/magisk|/data/adb/modules|com\.topjohnwu\.magisk')
ZYGISK_RE = re.compile(r'zygisk|libzygisk|/data/adb/zygisk')
RIRU_RE = re.compile(r'riru|libriru|/data/misc/riru')
DAEMON_SOCKET_RE = re.compile(r'@magisk|MAGISKHIDE|magiskd|prop_service')
# presence != usage: a bare "magisk"/"zygisk" substring in a .so can come from
# an unrelated dependency string table. For native libs, require a *contextual*
# marker (a path the app would stat() or a known framework symbol), not just
# the brand name, before counting it as a detection mechanism.
MAGISK_SO_CONTEXT_RE = re.compile(
    rb'/sbin/\.magisk|/data/adb/magisk|/data/adb/modules|com\.topjohnwu\.magisk|MagiskHide|magiskhide')
ZYGISK_SO_CONTEXT_RE = re.compile(rb'/data/adb/zygisk|libzygisk|zygisk_companion|zygisk_module')
RIRU_SO_CONTEXT_RE = re.compile(rb'/data/misc/riru|/data/adb/riru|libriru|riru_module')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["magisk_zygisk_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["magisk_zygisk_audit_error"] = str(e); return
    magisk_check, zygisk_check, riru_check, socket_check = [], [], [], []
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file(): continue
        if p.suffix == ".so":
            try: blob = p.read_bytes()
            except OSError: continue
            files_scanned += 1
            low = blob.lower()
            # Require a contextual path/symbol, not just the brand substring.
            if MAGISK_SO_CONTEXT_RE.search(low) and len(magisk_check) < 20:
                magisk_check.append(p.name)
            if ZYGISK_SO_CONTEXT_RE.search(low) and len(zygisk_check) < 20:
                zygisk_check.append(p.name)
            if RIRU_SO_CONTEXT_RE.search(low) and len(riru_check) < 20:
                riru_check.append(p.name)
            continue
        if p.suffix not in (".smali", ".swift", ".m", ".h"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if MAGISK_PATH_RE.search(txt) and len(magisk_check) < 20:
            magisk_check.append(p.name)
        if ZYGISK_RE.search(txt) and len(zygisk_check) < 20:
            zygisk_check.append(p.name)
        if RIRU_RE.search(txt) and len(riru_check) < 20:
            riru_check.append(p.name)
        if DAEMON_SOCKET_RE.search(txt) and len(socket_check) < 20:
            socket_check.append(p.name)
    findings_total = 0
    if not (magisk_check or zygisk_check or riru_check or socket_check):
        findings_total += 1
    ctx.state["magisk_checks"] = magisk_check[:20]
    ctx.state["zygisk_checks"] = zygisk_check[:20]
    ctx.state["riru_checks"] = riru_check[:20]
    ctx.state["daemon_socket_checks"] = socket_check[:20]
    ctx.state["files_scanned"] = files_scanned
    ctx.state["magisk_zygisk_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("Magisk path / class checks", "magisk_checks"),
                ("Zygisk references", "zygisk_checks"),
                ("Riru references", "riru_checks"),
                ("magiskd socket checks", "daemon_socket_checks")]


@router.post("/api/mobile_runtime/magisk_zygisk_audit")
async def mobile_runtime_magisk_zygisk_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="magisk_zygisk_audit",
        gather_func=gather, finding_rules=MAGISK_ZYGISK_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
