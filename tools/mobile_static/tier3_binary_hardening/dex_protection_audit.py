"""dex_protection_audit — commercial obfuscator / packer / RASP detection.

Beyond R8: detect commercial mobile-app shields. Their presence indicates
the dev team takes resilience seriously; their absence suggests R8-only
defense (bypassable in <1 hour by an experienced reverser).

MASVS-RESILIENCE-4 / MSTG-RESILIENCE-9.
"""
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.dex_protection_audit_findings import \
    DEX_PROTECTION_AUDIT_FINDING_RULES

router = APIRouter()

# (vendor, marker bytes)
SHIELDS = [
    ("DexGuard (Guardsquare)",       b"com/guardsquare/dexguard"),
    ("DexGuard (anti-tamper)",       b"dexguard"),
    ("Promon SHIELD",                b"com/promon/"),
    ("Arxan / Digital.ai",           b"com/arxan/"),
    ("Arxan / Digital.ai (alt)",     b"arxan_"),
    ("Verimatrix",                   b"com/verimatrix/"),
    ("Appdome",                      b"com/appdome/"),
    ("Approov (CriticalBlue)",       b"com/criticalblue/approov"),
    ("zShield (Zimperium)",          b"com/zimperium/"),
    ("BlueDot (Bitdefender)",        b"com/bitdefender/security/"),
    ("Allatori",                     b"AllatoriObfuscation"),
    ("Bangcle",                      b"com/secneo/apkwrapper/"),
    ("APK Protect",                  b"com/apkprotect/"),
    ("Tencent legu",                 b"com/tencent/StubShell"),
    ("Baidu protect",                b"com/baidu/protect/"),
]


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["dex_protection_audit_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["dex_protection_audit_error"] = str(e); return

    found = []
    files_scanned = 0
    for f in unpacked.rglob("*"):
        if not f.is_file(): continue
        if f.suffix not in (".dex", ".smali", ".so") and "classes" not in f.name: continue
        try:
            data = f.read_bytes()[:10_000_000]
        except Exception: continue
        files_scanned += 1
        for vendor, marker in SHIELDS:
            if marker in data and vendor not in [v["vendor"] for v in found]:
                found.append({"vendor": vendor, "marker": marker.decode(errors="ignore")})

    ctx.state["shields_found"] = found
    ctx.state["dex_protection_audit_total"] = len(found)
    ctx.state["files_scanned"] = files_scanned
    ctx.source(f"scanned {files_scanned}, {len(found)} shield(s) detected")


INTEL_FIELDS = [
    ("Mobile RASP/shields detected", "dex_protection_audit_total"),
    ("Files scanned",                 "files_scanned"),
]


@router.post("/api/mobile_static/dex_protection_audit")
async def mobile_static_dex_protection_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="dex_protection_audit",
        gather_func=gather,
        finding_rules=DEX_PROTECTION_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
