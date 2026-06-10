"""resource_id_obfuscation_audit — check R8 resource shrinking + obfuscation.

R8 resourceShrinker removes unused R.id constants and obfuscates layout/
drawable file names. Check if resources.arsc + resources/ has been
shrunk (typical R8-shrunk APK: <5MB res/; unshrunk: 20+MB).

Quick proxy: count of XML files in res/layout/ and res/drawable*/ — heavily
shrunk apps have low counts because R8 inlines/removes them.

MASVS-RESILIENCE-4 / general size-optimization.
"""
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.resource_id_obfuscation_audit_findings import \
    RESOURCE_ID_OBFUSCATION_AUDIT_FINDING_RULES

router = APIRouter()


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["resource_id_obfuscation_audit_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["resource_id_obfuscation_audit_error"] = str(e); return

    res_dir = unpacked / "res"
    if not res_dir.is_dir():
        ctx.state["resource_id_obfuscation_audit_total"] = 0
        ctx.source("no-res-dir"); return

    layouts = list(res_dir.glob("layout*/**/*.xml"))
    drawables = list(res_dir.glob("drawable*/**/*"))
    raw = list(res_dir.glob("raw/**/*"))
    res_total = sum(1 for _ in res_dir.rglob("*") if _.is_file())
    res_size_mb = sum(f.stat().st_size for f in res_dir.rglob("*") if f.is_file()) / 1024 / 1024

    # Short-name ratio in layout XMLs (R8 obfuscates these too sometimes)
    short_layouts = sum(1 for f in layouts if len(f.stem) <= 3)
    layout_total = len(layouts)
    if layout_total > 0:
        ratio = round(short_layouts / layout_total * 100, 1)
    else:
        ratio = -1

    ctx.state["res_total_files"] = res_total
    ctx.state["res_size_mb"] = round(res_size_mb, 2)
    ctx.state["layout_count"] = layout_total
    ctx.state["drawable_count"] = len(drawables)
    ctx.state["raw_count"] = len(raw)
    ctx.state["short_layout_ratio_pct"] = ratio
    ctx.state["resource_id_obfuscation_audit_total"] = res_total
    ctx.source(f"res/: {res_total} files, {round(res_size_mb,1)}MB")


INTEL_FIELDS = [
    ("Resource files",        "res_total_files"),
    ("Resource size (MB)",    "res_size_mb"),
    ("Layouts",                "layout_count"),
    ("Short-layout ratio (%)","short_layout_ratio_pct"),
]


@router.post("/api/mobile_static/resource_id_obfuscation_audit")
async def mobile_static_resource_id_obfuscation_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="resource_id_obfuscation_audit",
        gather_func=gather,
        finding_rules=RESOURCE_ID_OBFUSCATION_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
