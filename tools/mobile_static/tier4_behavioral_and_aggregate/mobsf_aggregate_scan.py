"""mobsf_aggregate_scan — MobSF static analysis if installed.

MobSF is a heavyweight optional dependency. If not present in container,
scanner emits a graceful POSITIVE indicating the scan was attempted
without MobSF. Lightweight aggregate using local tools serves as fallback.
"""
import hashlib
import shutil
import subprocess
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.mobsf_aggregate_scan_findings import MOBSF_AGGREGATE_SCAN_FINDING_RULES

router = APIRouter()


async def gather(ctx: ScanContext):
    apk_path = ctx.host
    if not Path(apk_path).is_file():
        ctx.state["mobsf_aggregate_scan_total"] = 0
        ctx.source("file-not-found")
        return

    # Quick file metadata that's always available
    apk = Path(apk_path)
    size_mb = apk.stat().st_size / (1024 * 1024)
    ctx.state["file_size_mb"] = round(size_mb, 2)

    # SHA-256 (useful for VirusTotal-style downstream lookups)
    h = hashlib.sha256()
    with apk.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    ctx.state["sha256"] = h.hexdigest()

    # If MobSF CLI is installed, invoke it. Otherwise produce best-effort aggregate.
    mobsf_bin = shutil.which("mobsfscan") or shutil.which("mobsf-cli")
    if mobsf_bin:
        try:
            r = subprocess.run([mobsf_bin, "--json", str(apk_path)],
                                capture_output=True, text=True, timeout=120)
            ctx.state["mobsf_output"] = r.stdout[:5000]  # cap to 5KB
            ctx.state["mobsf_aggregate_scan_total"] = 1 if r.returncode == 0 else 0
            ctx.source("mobsfscan")
        except (subprocess.TimeoutExpired, OSError):
            ctx.state["mobsf_error"] = "mobsf-timeout-or-error"
            ctx.state["mobsf_aggregate_scan_total"] = 0
    else:
        # Fallback aggregate — quick sanity checks
        try:
            unpacked = get_unpacked(apk_path)
            dex_count = len(list(unpacked.rglob("classes*.dex")))
            so_count  = len(list(unpacked.rglob("*.so")))
            ctx.state["dex_files"] = dex_count
            ctx.state["native_libs"] = so_count
            ctx.state["mobsf_aggregate_scan_total"] = 0  # no MobSF, no findings
            ctx.source("aggregate-fallback (MobSF not installed)")
        except Exception as e:
            ctx.state["mobsf_aggregate_scan_error"] = str(e)


INTEL_FIELDS = [
    ("SHA-256", "sha256"),
    ("Size (MB)", "file_size_mb"),
    ("DEX files", "dex_files"),
    ("Native libs", "native_libs"),
]


@router.post("/api/mobile_static/mobsf_aggregate_scan")
async def mobile_static_mobsf_aggregate_scan(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="mobsf_aggregate_scan",
        gather_func=gather,
        finding_rules=MOBSF_AGGREGATE_SCAN_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
