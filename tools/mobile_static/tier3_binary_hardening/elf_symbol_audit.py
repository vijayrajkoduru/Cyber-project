"""elf_symbol_audit — flag dangerous imports + missing strip in ELF binaries."""
import subprocess
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.elf_symbol_audit_findings import ELF_SYMBOL_AUDIT_FINDING_RULES

router = APIRouter()

DANGEROUS_IMPORTS = {
    "gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf",
    "system", "popen", "exec", "execve", "execvp",
}


def _is_elf(p: Path) -> bool:
    try:
        with p.open("rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def _nm_symbols(p: Path) -> tuple[list[str], bool]:
    """Returns (imported_dangerous_symbols, has_debug_symbols)."""
    try:
        r = subprocess.run(["nm", "-D", str(p)], capture_output=True, text=True, timeout=20)
    except (subprocess.TimeoutExpired, OSError):
        return [], False
    if r.returncode != 0:
        return [], False
    imports = []
    for line in r.stdout.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[-2] == "U":  # undefined = imported
            name = parts[-1].split("@")[0]
            if name in DANGEROUS_IMPORTS:
                imports.append(name)
    # Has debug symbols?
    has_debug = False
    try:
        r2 = subprocess.run(["file", str(p)], capture_output=True, text=True, timeout=10)
        has_debug = "not stripped" in r2.stdout
    except (subprocess.TimeoutExpired, OSError):
        pass
    return imports, has_debug


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["elf_symbol_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["elf_symbol_audit_error"] = str(e)
        return

    elfs = []
    # Bundled .so files
    for p in unpacked.rglob("*.so"):
        if _is_elf(p):
            elfs.append(p)
    # Top-level ELF (e.g. user uploaded a Linux executable directly)
    if _is_elf(Path(apk)):
        elfs.append(Path(apk))

    if not elfs:
        ctx.state["elf_symbol_audit_total"] = 0
        ctx.source("no-elf-binaries")
        return

    issues = []
    for elf in elfs[:30]:
        imports, has_debug = _nm_symbols(elf)
        if imports:
            issues.append({"file": elf.name, "dangerous_imports": list(set(imports))})
        if has_debug:
            issues.append({"file": elf.name, "issue": "unstripped-debug-symbols"})

    ctx.state["elf_issues"] = issues
    ctx.state["elf_symbol_audit_total"] = len(issues)
    ctx.state["elfs_audited"] = len(elfs)
    ctx.source("nm + file")


INTEL_FIELDS = [
    ("ELF issues", "elf_symbol_audit_total"),
    ("ELF binaries audited", "elfs_audited"),
]


@router.post("/api/mobile_static/elf_symbol_audit")
async def mobile_static_elf_symbol_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="elf_symbol_audit",
        gather_func=gather,
        finding_rules=ELF_SYMBOL_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
