"""aslr_textrel_audit - ASLR / PIE / text-relocation / lazy-binding audit.

Playbook §6 (Mitigation Bypass — DEP / ASLR / Canary / CFG):
  #53 ASLR bypass via info leak       (precondition: PIE/ASLR off)
  #54 ASLR bypass via partial overwrite
  #55 PIE bypass via leak             (precondition: PIE off)
  #57 Win 11 modern mitigations check (PE DYNAMICBASE / HIGHENTROPYVA / reloc)
  #58 RELRO partial -> full lazy-binding abuse (DT_BIND_NOW)

Real static decode focused on the address-space-randomization surface that
the binary_protection_audit starter only summarized:

  ELF:
    * PIE flag (ET_DYN with PT_INTERP)               -> pwntools ELF.pie
    * DF_TEXTREL / DT_TEXTREL  (writable .text relocs, breaks W^X + ASLR)
    * DT_BIND_NOW / DF_BIND_NOW (eager binding -> full-RELRO precondition)
    * DT_FLAGS_1 PIE marker
  PE:
    * DYNAMICBASE (ASLR), HIGH_ENTROPY_VA (64-bit), and the
      IMAGE_FILE_RELOCS_STRIPPED bit (which silently forces a fixed base
      even when DYNAMICBASE is set — a real, often-missed misconfiguration).

A graded finding fires ONLY when the decode actually shows the weakness on a
parsed binary.  TEXTREL is graded because it is a hard, decoded fact that
breaks ASLR + W^X; missing-PIE / missing-DYNAMICBASE mirror the protection
starter but here we add the RELOCS_STRIPPED contradiction check.

Customer input: ScanRequest.target = absolute path to an ELF / PE binary.
"""
from __future__ import annotations
import asyncio
import struct
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools.bof.tier1_protections.aslr_textrel_audit_findings import (
    ASLR_TEXTREL_AUDIT_FINDING_RULES,
)

router = APIRouter()
MAX_BINARY_SIZE_MB = 256

# Dynamic-section tags
DT_NULL = 0
DT_BIND_NOW = 24
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DT_TEXTREL = 22
DF_TEXTREL = 0x4
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1
DF_1_PIE = 0x08000000

PT_DYNAMIC = 2
PT_INTERP = 3
ET_DYN = 3


def _decode_elf_dynamic_flags(raw: bytes) -> dict:
    """Pure-python walk of the PT_DYNAMIC array to read DT_TEXTREL / DF_TEXTREL,
    DT_BIND_NOW / DF_BIND_NOW, and the DF_1_PIE marker."""
    out = {"textrel": False, "bind_now": False, "df1_pie": False,
           "has_dynamic": False, "et_dyn": False, "has_interp": False}
    if len(raw) < 64 or raw[:4] != b"\x7fELF":
        return out
    is64 = (raw[4] == 2)
    little = (raw[5] == 1)
    end = "<" if little else ">"
    try:
        e_type = struct.unpack_from(end + "H", raw, 16)[0]
        out["et_dyn"] = (e_type == ET_DYN)
        if is64:
            e_phoff = struct.unpack_from(end + "Q", raw, 32)[0]
            e_phentsize = struct.unpack_from(end + "H", raw, 54)[0]
            e_phnum = struct.unpack_from(end + "H", raw, 56)[0]
        else:
            e_phoff = struct.unpack_from(end + "I", raw, 28)[0]
            e_phentsize = struct.unpack_from(end + "H", raw, 42)[0]
            e_phnum = struct.unpack_from(end + "H", raw, 44)[0]
    except Exception:
        return out

    dyn_off = dyn_sz = 0
    try:
        for i in range(min(e_phnum, 256)):
            base = e_phoff + i * e_phentsize
            if base + e_phentsize > len(raw):
                break
            p_type = struct.unpack_from(end + "I", raw, base)[0]
            if p_type == PT_INTERP:
                out["has_interp"] = True
            if p_type == PT_DYNAMIC:
                if is64:
                    dyn_off = struct.unpack_from(end + "Q", raw, base + 8)[0]
                    dyn_sz = struct.unpack_from(end + "Q", raw, base + 32)[0]
                else:
                    dyn_off = struct.unpack_from(end + "I", raw, base + 4)[0]
                    dyn_sz = struct.unpack_from(end + "I", raw, base + 16)[0]
    except Exception:
        return out

    if not dyn_off or not dyn_sz:
        return out
    out["has_dynamic"] = True

    entry_sz = 16 if is64 else 8
    n = min(dyn_sz // entry_sz, 4096)
    try:
        for i in range(n):
            base = dyn_off + i * entry_sz
            if base + entry_sz > len(raw):
                break
            if is64:
                d_tag, d_val = struct.unpack_from(end + "qQ", raw, base)
            else:
                d_tag, d_val = struct.unpack_from(end + "iI", raw, base)
            if d_tag == DT_NULL:
                break
            if d_tag == DT_TEXTREL:
                out["textrel"] = True
            elif d_tag == DT_BIND_NOW:
                out["bind_now"] = True
            elif d_tag == DT_FLAGS:
                if d_val & DF_TEXTREL:
                    out["textrel"] = True
                if d_val & DF_BIND_NOW:
                    out["bind_now"] = True
            elif d_tag == DT_FLAGS_1:
                if d_val & DF_1_NOW:
                    out["bind_now"] = True
                if d_val & DF_1_PIE:
                    out["df1_pie"] = True
    except Exception:
        pass
    return out


def _audit_elf(path: Path) -> dict:
    try:
        from pwn import ELF, context
        context.log_level = "error"
    except ImportError as e:
        return {"_pwntools_missing": str(e)}
    try:
        elf = ELF(str(path), checksec=False)
    except Exception as e:
        return {"_elf_parse_error": str(e)}

    try:
        raw = path.read_bytes()
    except OSError as e:
        return {"_read_error": str(e)}

    dyn = _decode_elf_dynamic_flags(raw)

    relro_str = "none"
    try:
        if elf.relro is True:
            relro_str = "full"
        elif elf.relro == "Partial":
            relro_str = "partial"
        elif elf.relro:
            relro_str = str(elf.relro).lower()
    except Exception:
        pass

    pie = False
    try:
        pie = bool(elf.pie)
    except Exception:
        pie = dyn.get("df1_pie") and dyn.get("et_dyn") and dyn.get("has_interp")

    arch = bits = None
    try:
        arch = elf.arch
        bits = elf.bits
    except Exception:
        pass

    return {
        "kind": "elf",
        "arch": arch or "",
        "bits": bits or 0,
        "pie": bool(pie),
        "relro": relro_str,
        "textrel": bool(dyn.get("textrel")),
        "bind_now": bool(dyn.get("bind_now")),
        "static": bool(getattr(elf, "statically_linked", False)),
    }


def _audit_pe(path: Path) -> dict:
    try:
        import pefile  # type: ignore
    except ImportError as e:
        return {"_pefile_missing": str(e)}
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories()
    except Exception as e:
        return {"_pe_parse_error": str(e)}

    dll = int(pe.OPTIONAL_HEADER.DllCharacteristics)
    dynamicbase = bool(dll & 0x0040)        # DYNAMIC_BASE
    high_entropy = bool(dll & 0x0020)       # HIGH_ENTROPY_VA
    # File header characteristics: IMAGE_FILE_RELOCS_STRIPPED = 0x0001
    file_chars = int(pe.FILE_HEADER.Characteristics)
    relocs_stripped = bool(file_chars & 0x0001)

    bits = 64 if pe.OPTIONAL_HEADER.Magic == 0x20b else 32
    machine = pe.FILE_HEADER.Machine
    arch = {0x8664: "x86_64", 0x14c: "i386", 0xaa64: "arm64",
            0x1c4: "arm"}.get(machine, hex(machine))

    return {
        "kind": "pe",
        "arch": arch,
        "bits": bits,
        "dynamicbase": dynamicbase,
        "high_entropy_va": high_entropy,
        "relocs_stripped": relocs_stripped,
    }


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target:
        ctx.state["binary_path_missing"] = True
        ctx.source("no target path provided")
        return
    path = Path(target)
    if not path.is_file():
        ctx.state["binary_path_missing"] = True
        ctx.source(f"file not found: {target}")
        return
    try:
        size_mb = path.stat().st_size / (1024 * 1024)
    except OSError:
        size_mb = 0
    if size_mb > MAX_BINARY_SIZE_MB:
        ctx.state["binary_too_large_mb"] = round(size_mb, 1)
        ctx.source(f"binary too large: {round(size_mb, 1)} MB")
        return

    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError as e:
        ctx.state["binary_read_error"] = str(e)
        ctx.source(f"read error: {e}")
        return

    loop = asyncio.get_event_loop()
    if head[:4] == b"\x7fELF":
        info = await loop.run_in_executor(None, _audit_elf, path)
    elif head[:2] == b"MZ":
        info = await loop.run_in_executor(None, _audit_pe, path)
    else:
        ctx.state["binary_unknown_format"] = True
        ctx.source("unrecognized binary header")
        return

    for k in ("_pwntools_missing", "_pefile_missing"):
        if info.get(k):
            ctx.state["library_missing"] = f"{k}: {info[k]}"
            ctx.source(f"library missing: {k}")
            return
    for k in ("_elf_parse_error", "_pe_parse_error", "_read_error"):
        if info.get(k):
            ctx.state["parse_error"] = f"{k}: {info[k]}"
            ctx.source(f"parse error: {k}")
            return

    ctx.state["aslr_info"] = info
    ctx.state["binary_kind"] = info.get("kind")
    ctx.state["binary_arch"] = info.get("arch")
    if info.get("kind") == "elf":
        ctx.source(
            f"ELF {info.get('arch')}/{info.get('bits')}bit ASLR decode: "
            f"PIE={info.get('pie')} RELRO={info.get('relro')} "
            f"TEXTREL={info.get('textrel')} BIND_NOW={info.get('bind_now')}"
        )
    else:
        ctx.source(
            f"PE {info.get('arch')}/{info.get('bits')}bit ASLR decode: "
            f"DYNAMICBASE={info.get('dynamicbase')} "
            f"HIGH_ENTROPY={info.get('high_entropy_va')} "
            f"RELOCS_STRIPPED={info.get('relocs_stripped')}"
        )


INTEL_FIELDS = [
    ("Binary kind",       "binary_kind"),
    ("Architecture",      "binary_arch"),
    ("ASLR / PIE decode", "aslr_info"),
]


@router.post("/api/bof/aslr_textrel_audit")
async def bof_aslr_textrel_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target,
        tool="aslr_textrel_audit",
        gather_func=gather,
        finding_rules=ASLR_TEXTREL_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
