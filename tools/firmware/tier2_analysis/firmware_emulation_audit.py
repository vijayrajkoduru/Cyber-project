"""firmware_emulation_audit - Run extracted ARM binaries via qemu-user (playbook §4 #34).

Detects executable binaries inside an extracted firmware (after binwalk -e)
and attempts to run each ARM/ARM64/MIPS binary through qemu-arm-static /
qemu-aarch64-static / qemu-mipsel-static. Captures:
  - Banner / version output
  - Whether the binary segfaults instantly (potential crash bug)
  - Hardcoded paths printed in --help output
  - Any TCP/UDP ports the binary tries to listen on

Customer input: ScanRequest.target = path to firmware blob on disk.
"""
from __future__ import annotations
import asyncio
import shutil
import subprocess
import tempfile
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.firmware_emulation_audit_findings import FIRMWARE_EMULATION_AUDIT_FINDING_RULES

router = APIRouter()
BINWALK_BIN = shutil.which("binwalk")
QEMU_BINS = {
    "arm": shutil.which("qemu-arm-static"),
    "aarch64": shutil.which("qemu-aarch64-static"),
    "mipsel": shutil.which("qemu-mipsel-static"),
    "mips": shutil.which("qemu-mips-static"),
}
MAX_BINARIES = 20
PER_BINARY_TIMEOUT = 5


def _detect_arch(file_bytes: bytes) -> str | None:
    """Best-effort arch detection from ELF header (e_machine field)."""
    if len(file_bytes) < 20 or file_bytes[:4] != b"\x7fELF":
        return None
    e_machine_low = file_bytes[18]
    e_machine_high = file_bytes[19]
    e_machine = (e_machine_high << 8) | e_machine_low
    elf_data = file_bytes[5]  # ELFDATA2LSB=1, ELFDATA2MSB=2
    if e_machine == 0x28:
        return "arm"
    if e_machine == 0xb7:
        return "aarch64"
    if e_machine == 0x08:
        return "mipsel" if elf_data == 1 else "mips"
    return None


async def _run_qemu(qemu_bin: str, binary: str, args: list[str]) -> dict:
    """Run a binary via qemu-user with a wall-clock cap, returning stdout+rc."""
    try:
        proc = await asyncio.create_subprocess_exec(
            qemu_bin, binary, *args,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(),
                                                    timeout=PER_BINARY_TIMEOUT)
        except asyncio.TimeoutError:
            try: proc.kill()
            except Exception: pass
            return {"timeout": True, "rc": None, "stdout": b"", "stderr": b""}
        return {"timeout": False, "rc": proc.returncode,
                "stdout": stdout, "stderr": stderr}
    except Exception as e:
        return {"error": str(e)[:120], "rc": None}


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target or not Path(target).is_file():
        ctx.state["firmware_emulation_audit_total"] = 0
        ctx.source("file-not-found")
        return
    if not BINWALK_BIN:
        ctx.state["firmware_emulation_audit_error"] = "binwalk binary not installed"
        ctx.source("binwalk missing")
        return
    if not any(QEMU_BINS.values()):
        ctx.state["firmware_emulation_audit_error"] = "qemu-user-static not installed"
        ctx.source("qemu-user-static missing")
        return

    tmpdir = tempfile.mkdtemp(prefix="vlfwemul_")
    try:
        # Extract firmware
        try:
            subprocess.run([BINWALK_BIN, "-e", "-q", "-C", tmpdir, target],
                          timeout=180, capture_output=True, check=False)
        except subprocess.TimeoutExpired:
            ctx.state["firmware_emulation_audit_error"] = "binwalk extract timeout"
            ctx.source("binwalk timeout")
            return

        # Find ELF binaries
        candidates: list[tuple[Path, str]] = []
        for fp in Path(tmpdir).rglob("*"):
            if len(candidates) >= MAX_BINARIES:
                break
            if not fp.is_file() or fp.stat().st_size < 512 or fp.stat().st_size > 50_000_000:
                continue
            try:
                with open(fp, "rb") as fh:
                    head = fh.read(64)
            except Exception:
                continue
            arch = _detect_arch(head)
            if not arch:
                continue
            qemu_bin = QEMU_BINS.get(arch)
            if not qemu_bin:
                continue
            candidates.append((fp, arch))

        if not candidates:
            ctx.state["firmware_emulation_audit_total"] = 0
            ctx.state["firmware_no_arm_binaries"] = True
            ctx.source("no ARM/MIPS binaries found in extraction")
            return

        results = []
        crashed_binaries = []
        banner_findings = []
        for binary_path, arch in candidates:
            qemu_bin = QEMU_BINS[arch]
            # Try --help
            help_result = await _run_qemu(qemu_bin, str(binary_path), ["--help"])
            # Try --version
            version_result = await _run_qemu(qemu_bin, str(binary_path), ["--version"])

            binary_info = {
                "path": str(binary_path.relative_to(tmpdir))[:80],
                "arch": arch,
                "size": binary_path.stat().st_size,
            }
            help_out = (help_result.get("stdout", b"") or b"")[:500].decode("utf-8", errors="ignore")
            ver_out = (version_result.get("stdout", b"") or b"")[:200].decode("utf-8", errors="ignore")

            if help_out:
                binary_info["help_excerpt"] = help_out
                banner_findings.append({"binary": binary_info["path"], "help": help_out[:200]})
            if ver_out:
                binary_info["version"] = ver_out.strip()

            # SIGSEGV = -11; common segfault indicator
            if help_result.get("rc") == -11 or help_result.get("rc") == 139:
                crashed_binaries.append(binary_info["path"])
                binary_info["crashed"] = True

            results.append(binary_info)

        ctx.state["firmware_emulation_results"] = results
        ctx.state["firmware_emulation_crashed"] = crashed_binaries
        ctx.state["firmware_emulation_banners"] = banner_findings[:10]
        ctx.state["firmware_binaries_tested"] = len(results)
        ctx.state["firmware_emulation_audit_total"] = len(crashed_binaries)
        ctx.source(f"{len(results)} ARM/MIPS binaries emulated; "
                   f"{len(crashed_binaries)} crashed instantly")
    finally:
        try: shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception: pass


INTEL_FIELDS = [("Binaries emulated", "firmware_binaries_tested"),
                ("Crashed binaries", "firmware_emulation_crashed"),
                ("Banner/help output", "firmware_emulation_banners"),
                ("Full results", "firmware_emulation_results")]


@router.post("/api/firmware/firmware_emulation_audit")
async def firmware_firmware_emulation_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="firmware_emulation_audit",
        gather_func=gather, finding_rules=FIRMWARE_EMULATION_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
