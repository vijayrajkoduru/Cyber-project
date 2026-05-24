"""pe_hardening_audit — Windows PE binary mitigation audit via pefile."""
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.pe_hardening_audit_findings import PE_HARDENING_AUDIT_FINDING_RULES

router = APIRouter()


def _audit_pe(pe_path: Path) -> dict | None:
    """Returns dict of mitigation flags, or None if not a valid PE."""
    try:
        import pefile
    except ImportError:
        return None
    try:
        pe = pefile.PE(str(pe_path), fast_load=True)
    except Exception:
        return None
    try:
        dll_ch = pe.OPTIONAL_HEADER.DllCharacteristics
        return {
            "file": pe_path.name,
            "ASLR":          bool(dll_ch & 0x0040),  # DYNAMIC_BASE
            "DEP":           bool(dll_ch & 0x0100),  # NX_COMPAT
            "CFG":           bool(dll_ch & 0x4000),  # GUARD_CF
            "SafeSEH":       bool(getattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG", None)),
            "HighEntropyVA": bool(dll_ch & 0x0020),
        }
    finally:
        pe.close()


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["pe_hardening_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["pe_hardening_audit_error"] = str(e)
        return

    # PE files in zip OR the binary itself
    pe_files = []
    if Path(apk).suffix.lower() in (".exe", ".dll", ".sys") or Path(apk).stat().st_size > 0:
        # Standalone PE — check if it's a PE binary
        try:
            with Path(apk).open("rb") as f:
                if f.read(2) == b"MZ":
                    pe_files.append(Path(apk))
        except OSError:
            pass

    # Or PE files inside the archive (some Windows apps ship dlls)
    for p in unpacked.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() in (".exe", ".dll", ".sys", ".ocx"):
            pe_files.append(p)

    if not pe_files:
        ctx.state["pe_hardening_audit_total"] = 0
        ctx.source("no-pe-files")
        return

    weak_pes = []
    for pe in pe_files[:20]:
        flags = _audit_pe(pe)
        if not flags:
            continue
        missing = [k for k in ("ASLR", "DEP", "CFG") if not flags.get(k)]
        if missing:
            weak_pes.append({"file": flags["file"], "missing": missing})

    ctx.state["weak_pe_binaries"] = weak_pes
    ctx.state["pe_hardening_audit_total"] = len(weak_pes)
    ctx.state["pe_files_audited"] = len(pe_files)
    ctx.source("pefile")


INTEL_FIELDS = [
    ("Weak PE binaries", "pe_hardening_audit_total"),
    ("PE files audited", "pe_files_audited"),
]


@router.post("/api/mobile_static/pe_hardening_audit")
async def mobile_static_pe_hardening_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="pe_hardening_audit",
        gather_func=gather,
        finding_rules=PE_HARDENING_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
