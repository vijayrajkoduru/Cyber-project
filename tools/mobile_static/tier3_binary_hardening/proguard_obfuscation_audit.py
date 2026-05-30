"""proguard_obfuscation_audit — detect ProGuard/R8 code obfuscation.

Apps shipping unobfuscated class/method names make reverse engineering
trivial. Real protection: ProGuard / R8 short-name obfuscation. Apps
with mostly long descriptive class names (com.acme.banking.PaymentProcessor)
weren't obfuscated. Apps with mostly single-letter names (a.b.c)
were obfuscated.

MASVS-RESILIENCE-4 / MSTG-RESILIENCE-9.
"""
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.proguard_obfuscation_audit_findings import \
    PROGUARD_OBFUSCATION_AUDIT_FINDING_RULES

router = APIRouter()
# Extract DEX class signature names: Lcom/acme/Foo$Bar;
CLASS_RE = re.compile(rb"L[\w/$]{1,200};")


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["proguard_obfuscation_audit_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["proguard_obfuscation_audit_error"] = str(e); return

    short = 0      # class names with 1-2 char last segments
    long_named = 0 # class names with >5 char last segments
    third_party = 0
    own_classes = 0
    files_scanned = 0
    sample_long = []

    for f in unpacked.rglob("*"):
        if not f.is_file(): continue
        if "classes" not in f.name or f.suffix != ".dex": continue
        try:
            data = f.read_bytes()[:30_000_000]
        except Exception: continue
        files_scanned += 1
        for m in CLASS_RE.finditer(data):
            name = m.group(0).decode(errors="ignore")[1:-1]  # strip L...;
            # Skip well-known third-party prefixes
            if name.startswith(("java/", "kotlin/", "kotlinx/", "android/",
                                  "androidx/", "com/google/", "com/android/",
                                  "javax/", "org/jetbrains/")):
                third_party += 1
                continue
            own_classes += 1
            last = name.rsplit("/", 1)[-1].split("$")[0]
            if len(last) <= 2:
                short += 1
            elif len(last) > 5:
                long_named += 1
                if len(sample_long) < 15:
                    sample_long.append(name)
        if files_scanned >= 5: break  # cap to first 5 DEX files

    if own_classes == 0:
        ratio = -1
    else:
        ratio = round(short / own_classes * 100, 1)

    ctx.state["short_name_ratio_pct"] = ratio
    ctx.state["own_classes"] = own_classes
    ctx.state["short_names"] = short
    ctx.state["long_names"] = long_named
    ctx.state["sample_long_names"] = sample_long
    ctx.state["third_party_classes"] = third_party
    ctx.state["proguard_obfuscation_audit_total"] = own_classes
    ctx.state["files_scanned"] = files_scanned
    ctx.source(f"scanned {files_scanned} DEX, own_cls={own_classes}, short_ratio={ratio}%")


INTEL_FIELDS = [
    ("Own classes",         "own_classes"),
    ("Short-name ratio (%)","short_name_ratio_pct"),
    ("3rd-party classes",   "third_party_classes"),
    ("DEX files scanned",   "files_scanned"),
]


@router.post("/api/mobile_static/proguard_obfuscation_audit")
async def mobile_static_proguard_obfuscation_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="proguard_obfuscation_audit",
        gather_func=gather,
        finding_rules=PROGUARD_OBFUSCATION_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
