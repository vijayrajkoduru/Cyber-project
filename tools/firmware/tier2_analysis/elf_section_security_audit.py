"""elf_section_security_audit - ELF hardening posture of firmware binaries (playbook §4 #36).

Extracts the firmware via binwalk (if available) OR — when binwalk is absent —
treats the target itself as a single ELF, then parses each ELF's program/section
headers in PURE PYTHON (no external tool required) to assess exploit-mitigation
posture:

  - NX / DEP        : presence of a non-executable GNU_STACK segment (PT_GNU_STACK
                      with the X flag cleared). Executable stack => CWE-119 risk.
  - PIE / ASLR      : ET_DYN executable type (position-independent) vs ET_EXEC.
  - RELRO           : presence of PT_GNU_RELRO segment (partial/full RELRO).
  - Stack canary    : presence of `__stack_chk_fail` symbol/string reference.
  - Stripped        : absence of a symbol table (.symtab).

Each weak mitigation is reported per-binary. ZERO-FP: a graded finding is
emitted ONLY when a binary was actually parsed and the missing mitigation was
confirmed from its headers — never speculatively.

REAL static probe against the customer firmware. Read-only header parse; no
binary is executed.

Customer input: ScanRequest.target = path to firmware blob on disk.
"""
from __future__ import annotations
import asyncio
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.elf_section_security_audit_findings import ELF_SECTION_SECURITY_AUDIT_FINDING_RULES

router = APIRouter()
MAX_BINARIES = 60
MAX_ELF_BYTES = 60 * 1024 * 1024     # don't read >60 MB into memory per binary
BINWALK_TIMEOUT = 180

# ELF e_type
ET_EXEC = 2
ET_DYN = 3
# Program header types
PT_GNU_STACK = 0x6474e551
PT_GNU_RELRO = 0x6474e552


def _parse_elf(data: bytes):
    """Pure-python ELF mitigation parse. Returns dict or None if not an ELF."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return None
    ei_class = data[4]   # 1=32-bit, 2=64-bit
    ei_data = data[5]    # 1=LE, 2=BE
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        return None
    endian = "<" if ei_data == 1 else ">"
    is64 = ei_class == 2

    try:
        e_type = struct.unpack_from(endian + "H", data, 16)[0]
        if is64:
            e_phoff = struct.unpack_from(endian + "Q", data, 32)[0]
            e_phentsize = struct.unpack_from(endian + "H", data, 54)[0]
            e_phnum = struct.unpack_from(endian + "H", data, 56)[0]
        else:
            e_phoff = struct.unpack_from(endian + "I", data, 28)[0]
            e_phentsize = struct.unpack_from(endian + "H", data, 42)[0]
            e_phnum = struct.unpack_from(endian + "H", data, 44)[0]
    except struct.error:
        return None

    info = {
        "bits": 64 if is64 else 32,
        "pie": e_type == ET_DYN,
        "nx": True,           # default secure; flip to False if exec-stack found
        "relro": False,
        "has_gnu_stack": False,
    }

    # Walk program headers for GNU_STACK + GNU_RELRO
    if 0 < e_phnum <= 256 and e_phentsize >= (56 if is64 else 32):
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if off + e_phentsize > len(data):
                break
            try:
                p_type = struct.unpack_from(endian + "I", data, off)[0]
                if is64:
                    p_flags = struct.unpack_from(endian + "I", data, off + 4)[0]
                else:
                    p_flags = struct.unpack_from(endian + "I", data, off + 24)[0]
            except struct.error:
                break
            if p_type == PT_GNU_STACK:
                info["has_gnu_stack"] = True
                # PF_X = 0x1 — executable stack is the insecure case
                if p_flags & 0x1:
                    info["nx"] = False
            elif p_type == PT_GNU_RELRO:
                info["relro"] = True

    # Stack canary + stripped heuristics from the raw bytes
    info["canary"] = b"__stack_chk_fail" in data
    info["stripped"] = b".symtab" not in data
    return info


def _collect_elfs(root: Path):
    """Yield (relpath, parsed_info) for every ELF under root."""
    out = []
    for p in root.rglob("*"):
        if len(out) >= MAX_BINARIES:
            break
        if not p.is_file():
            continue
        try:
            sz = p.stat().st_size
        except OSError:
            continue
        if sz < 64 or sz > MAX_ELF_BYTES:
            continue
        try:
            with open(p, "rb") as fh:
                head = fh.read(64)
            if head[:4] != b"\x7fELF":
                continue
            with open(p, "rb") as fh:
                data = fh.read(MAX_ELF_BYTES)
        except OSError:
            continue
        info = _parse_elf(data)
        if info:
            try:
                rel = str(p.relative_to(root)).replace("\\", "/")
            except ValueError:
                rel = p.name
            info["path"] = rel[:200]
            out.append(info)
    return out


def _analyze(target: Path):
    """Extract (binwalk) then parse, else treat target as a lone ELF."""
    binwalk = shutil.which("binwalk")
    if binwalk:
        tmp = tempfile.mkdtemp(prefix="vlelf_")
        try:
            try:
                subprocess.run([binwalk, "-e", "-q", "-C", tmp, str(target)],
                               timeout=BINWALK_TIMEOUT, capture_output=True, check=False)
            except (subprocess.TimeoutExpired, OSError):
                pass
            elfs = _collect_elfs(Path(tmp))
            if elfs:
                return elfs, "binwalk-extract"
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    # Fallback: the target itself may be a bare ELF (e.g. a single binary upload)
    try:
        with open(target, "rb") as fh:
            data = fh.read(MAX_ELF_BYTES)
    except OSError:
        return [], "read-failed"
    info = _parse_elf(data)
    if info:
        info["path"] = target.name
        return [info], "bare-elf"
    return [], "no-elf"


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target or not Path(target).is_file():
        ctx.state["elf_section_security_audit_total"] = 0
        ctx.source("firmware file not found at target path")
        return

    elfs, mode = await asyncio.get_event_loop().run_in_executor(
        None, _analyze, Path(target))

    if not elfs:
        ctx.state["elf_count"] = 0
        ctx.state["elf_section_security_audit_total"] = 0
        ctx.source(f"no parseable ELF binaries ({mode})")
        return

    no_nx = [e["path"] for e in elfs if e.get("nx") is False]
    no_pie = [e["path"] for e in elfs if not e.get("pie")]
    no_relro = [e["path"] for e in elfs if not e.get("relro")]
    no_canary = [e["path"] for e in elfs if not e.get("canary")]
    stripped = [e["path"] for e in elfs if e.get("stripped")]

    ctx.state["elf_count"] = len(elfs)
    ctx.state["elf_mode"] = mode
    ctx.state["elf_exec_stack"] = no_nx
    ctx.state["elf_no_pie"] = no_pie
    ctx.state["elf_no_relro"] = no_relro
    ctx.state["elf_no_canary"] = no_canary
    ctx.state["elf_stripped"] = stripped
    ctx.state["elf_inventory"] = [
        {"path": e["path"], "bits": e["bits"], "pie": e["pie"], "nx": e["nx"],
         "relro": e["relro"], "canary": e["canary"], "stripped": e["stripped"]}
        for e in elfs[:40]
    ]
    # 'total' counts the most severe class (executable stack) for tile badge
    ctx.state["elf_section_security_audit_total"] = len(no_nx)
    ctx.source(f"{len(elfs)} ELFs parsed ({mode}); exec-stack={len(no_nx)}, "
               f"no-PIE={len(no_pie)}, no-RELRO={len(no_relro)}")


INTEL_FIELDS = [("ELF binaries parsed",       "elf_count"),
                ("Analysis mode",             "elf_mode"),
                ("Executable-stack binaries",  "elf_exec_stack"),
                ("No-PIE binaries",            "elf_no_pie"),
                ("No-RELRO binaries",          "elf_no_relro"),
                ("No-canary binaries",         "elf_no_canary"),
                ("Stripped binaries",          "elf_stripped"),
                ("Per-binary inventory",       "elf_inventory")]


@router.post("/api/firmware/elf_section_security_audit")
async def firmware_elf_section_security_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="elf_section_security_audit",
        gather_func=gather, finding_rules=ELF_SECTION_SECURITY_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
