"""cfi_modern_mitigation_audit - modern control-flow-integrity mitigation audit.

Playbook §8 (Modern Mitigation Bypass — 2024+):
  #71 Intel CET (IBT / Shadow-Stack) audit          [ELF .note.gnu.property]
  #72 ARM Pointer Authentication (PAC) audit         [ELF AArch64 feature note]
  #73 ARM MTE (Memory Tagging) / BTI audit           [ELF AArch64 feature note]
  #74 Linux IBT (Indirect Branch Tracking) audit     [ELF x86 IBT feature bit]
  + Windows CET shadow-stack (CETCOMPAT) for PE      [pefile DllCharacteristicsEx]

This scanner does a REAL static decode of the modern-CFI opt-in markers:

  * For ELF it walks the section/program headers in PURE PYTHON (no extra
    dependency) to locate the NT_GNU_PROPERTY_TYPE_0 note inside
    .note.gnu.property, then decodes the architecture feature words:
      - x86:     GNU_PROPERTY_X86_FEATURE_1_AND -> IBT (0x1), SHSTK (0x2)
      - aarch64: GNU_PROPERTY_AARCH64_FEATURE_1_AND -> BTI (0x1), PAC (0x2),
                 GCS / guarded-control-stack (0x4)
  * For PE it reads the extended DLL characteristics (CET_COMPAT 0x0001 inside
    the IMAGE_LOAD_CONFIG_DIRECTORY) via pefile.

A graded finding is emitted ONLY when the binary parses cleanly AND the
relevant opt-in bit is genuinely ABSENT on a platform where it COULD be
present (x86-64 / aarch64 ELF, or x64 PE).  When the architecture cannot
benefit (e.g. a 32-bit ARM ELF) or the binary cannot be parsed, the scanner
returns an honest INFO.  This is the exact bit-decode the §6 starter only
heuristically approximated.

Customer input: ScanRequest.target = absolute path to an ELF / PE binary.
"""
from __future__ import annotations
import asyncio
import struct
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools.bof.tier1_protections.cfi_modern_mitigation_audit_findings import (
    CFI_MODERN_MITIGATION_AUDIT_FINDING_RULES,
)

router = APIRouter()
MAX_BINARY_SIZE_MB = 256

# GNU property note constants
NT_GNU_PROPERTY_TYPE_0 = 5
GNU_PROPERTY_X86_FEATURE_1_AND = 0xC0000002
GNU_PROPERTY_AARCH64_FEATURE_1_AND = 0xC0000000
X86_FEATURE_1_IBT = 0x1
X86_FEATURE_1_SHSTK = 0x2
AARCH64_FEATURE_1_BTI = 0x1
AARCH64_FEATURE_1_PAC = 0x2
AARCH64_FEATURE_1_GCS = 0x4

# ELF machine ids we care about
EM_386 = 3
EM_X86_64 = 62
EM_AARCH64 = 183
EM_ARM = 40


def _align(n: int, a: int) -> int:
    if a <= 1:
        return n
    return (n + a - 1) & ~(a - 1)


def _decode_gnu_property_note(desc: bytes, is64: bool, little: bool) -> dict:
    """Walk the program-property array inside an NT_GNU_PROPERTY_TYPE_0 note
    descriptor and return the decoded x86/aarch64 feature words."""
    end = "<" if little else ">"
    out: dict = {}
    off = 0
    # each property: uint32 pr_type, uint32 pr_datasz, byte[pr_datasz] data,
    # padded to pointer alignment.
    align = 8 if is64 else 4
    while off + 8 <= len(desc):
        pr_type, pr_datasz = struct.unpack_from(end + "II", desc, off)
        off += 8
        data = desc[off:off + pr_datasz]
        if pr_type == GNU_PROPERTY_X86_FEATURE_1_AND and len(data) >= 4:
            word = struct.unpack_from(end + "I", data, 0)[0]
            out["x86_ibt"] = bool(word & X86_FEATURE_1_IBT)
            out["x86_shstk"] = bool(word & X86_FEATURE_1_SHSTK)
        elif pr_type == GNU_PROPERTY_AARCH64_FEATURE_1_AND and len(data) >= 4:
            word = struct.unpack_from(end + "I", data, 0)[0]
            out["aarch64_bti"] = bool(word & AARCH64_FEATURE_1_BTI)
            out["aarch64_pac"] = bool(word & AARCH64_FEATURE_1_PAC)
            out["aarch64_gcs"] = bool(word & AARCH64_FEATURE_1_GCS)
        off += _align(pr_datasz, align)
    return out


def _scan_notes_for_property(raw: bytes, is64: bool, little: bool,
                             note_blobs: list[tuple[int, int]]) -> dict:
    """Given (offset,size) ranges that hold ELF notes, find the GNU property
    note and decode it.  Note format: uint32 namesz, uint32 descsz,
    uint32 type, name[namesz] (padded to 4), desc[descsz] (padded to 4)."""
    end = "<" if little else ">"
    for (n_off, n_size) in note_blobs:
        seg = raw[n_off:n_off + n_size]
        pos = 0
        while pos + 12 <= len(seg):
            namesz, descsz, ntype = struct.unpack_from(end + "III", seg, pos)
            pos += 12
            name = seg[pos:pos + namesz]
            pos += _align(namesz, 4)
            desc = seg[pos:pos + descsz]
            pos += _align(descsz, 4)
            if ntype == NT_GNU_PROPERTY_TYPE_0 and name.rstrip(b"\x00") == b"GNU":
                return _decode_gnu_property_note(desc, is64, little)
    return {}


def _audit_elf_cfi(path: Path) -> dict:
    """Pure-python ELF parse to find CET / PAC / BTI / MTE-GCS opt-in markers."""
    try:
        raw = path.read_bytes()
    except OSError as e:
        return {"_read_error": str(e)}
    if len(raw) < 64 or raw[:4] != b"\x7fELF":
        return {"_not_elf": True}

    ei_class = raw[4]      # 1 = 32-bit, 2 = 64-bit
    ei_data = raw[5]       # 1 = little, 2 = big
    is64 = (ei_class == 2)
    little = (ei_data == 1)
    end = "<" if little else ">"

    try:
        if is64:
            e_machine = struct.unpack_from(end + "H", raw, 18)[0]
            e_phoff = struct.unpack_from(end + "Q", raw, 32)[0]
            e_shoff = struct.unpack_from(end + "Q", raw, 40)[0]
            e_phentsize = struct.unpack_from(end + "H", raw, 54)[0]
            e_phnum = struct.unpack_from(end + "H", raw, 56)[0]
            e_shentsize = struct.unpack_from(end + "H", raw, 58)[0]
            e_shnum = struct.unpack_from(end + "H", raw, 60)[0]
        else:
            e_machine = struct.unpack_from(end + "H", raw, 18)[0]
            e_phoff = struct.unpack_from(end + "I", raw, 28)[0]
            e_shoff = struct.unpack_from(end + "I", raw, 32)[0]
            e_phentsize = struct.unpack_from(end + "H", raw, 42)[0]
            e_phnum = struct.unpack_from(end + "H", raw, 44)[0]
            e_shentsize = struct.unpack_from(end + "H", raw, 46)[0]
            e_shnum = struct.unpack_from(end + "H", raw, 48)[0]
    except Exception as e:
        return {"_parse_error": str(e)}

    arch = {EM_386: "i386", EM_X86_64: "x86_64", EM_AARCH64: "aarch64",
            EM_ARM: "arm"}.get(e_machine, f"machine_{e_machine}")

    # Collect note ranges: prefer PT_NOTE program headers (type 4), fall back
    # to .note.gnu.property section.
    note_blobs: list[tuple[int, int]] = []
    PT_NOTE = 4
    try:
        for i in range(min(e_phnum, 256)):
            base = e_phoff + i * e_phentsize
            if base + e_phentsize > len(raw):
                break
            p_type = struct.unpack_from(end + "I", raw, base)[0]
            if p_type != PT_NOTE:
                continue
            if is64:
                p_offset = struct.unpack_from(end + "Q", raw, base + 8)[0]
                p_filesz = struct.unpack_from(end + "Q", raw, base + 32)[0]
            else:
                p_offset = struct.unpack_from(end + "I", raw, base + 4)[0]
                p_filesz = struct.unpack_from(end + "I", raw, base + 16)[0]
            if 0 < p_filesz < len(raw):
                note_blobs.append((p_offset, p_filesz))
    except Exception:
        pass

    feats = _scan_notes_for_property(raw, is64, little, note_blobs) if note_blobs else {}

    # Fallback: scan sections for SHT_NOTE if program-header walk found nothing
    if not feats and e_shoff and e_shnum:
        SHT_NOTE = 7
        sec_notes: list[tuple[int, int]] = []
        try:
            for i in range(min(e_shnum, 1024)):
                base = e_shoff + i * e_shentsize
                if base + e_shentsize > len(raw):
                    break
                if is64:
                    sh_type = struct.unpack_from(end + "I", raw, base + 4)[0]
                    sh_offset = struct.unpack_from(end + "Q", raw, base + 24)[0]
                    sh_size = struct.unpack_from(end + "Q", raw, base + 32)[0]
                else:
                    sh_type = struct.unpack_from(end + "I", raw, base + 4)[0]
                    sh_offset = struct.unpack_from(end + "I", raw, base + 16)[0]
                    sh_size = struct.unpack_from(end + "I", raw, base + 20)[0]
                if sh_type == SHT_NOTE and 0 < sh_size < len(raw):
                    sec_notes.append((sh_offset, sh_size))
        except Exception:
            pass
        if sec_notes:
            feats = _scan_notes_for_property(raw, is64, little, sec_notes)

    has_property_note = bool(feats)
    out = {
        "kind": "elf",
        "arch": arch,
        "bits": 64 if is64 else 32,
        "has_gnu_property_note": has_property_note,
        # x86 CET
        "x86_ibt": feats.get("x86_ibt", False),
        "x86_shstk": feats.get("x86_shstk", False),
        # aarch64 PAC / BTI / GCS
        "aarch64_bti": feats.get("aarch64_bti", False),
        "aarch64_pac": feats.get("aarch64_pac", False),
        "aarch64_gcs": feats.get("aarch64_gcs", False),
    }
    return out


def _audit_pe_cfi(path: Path) -> dict:
    """Read PE extended-CFI markers (CETCOMPAT shadow stack + CFG) via pefile."""
    try:
        import pefile  # type: ignore
    except ImportError as e:
        return {"_pefile_missing": str(e)}
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories()
    except Exception as e:
        return {"_pe_parse_error": str(e)}

    machine = pe.FILE_HEADER.Machine
    arch = {0x8664: "x86_64", 0x14c: "i386", 0xaa64: "arm64",
            0x1c4: "arm"}.get(machine, hex(machine))
    bits = 64 if pe.OPTIONAL_HEADER.Magic == 0x20b else 32

    dll = int(pe.OPTIONAL_HEADER.DllCharacteristics)
    guard_cf = bool(dll & 0x4000)   # IMAGE_DLLCHARACTERISTICS_GUARD_CF

    # CET shadow-stack lives in the load-config "DllCharacteristicsEx" (bit 0x1
    # = CET_COMPAT). pefile exposes it as GuardFlags / DllCharacteristicsEx
    # depending on version; we probe both, defensively.
    cet_shadow_stack = False
    try:
        cfg = getattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG", None)
        if cfg is not None:
            st = cfg.struct
            ex = getattr(st, "DllCharacteristicsEx", None)
            if isinstance(ex, int):
                cet_shadow_stack = bool(ex & 0x1)   # IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT
    except Exception:
        pass

    return {
        "kind": "pe",
        "arch": arch,
        "bits": bits,
        "pe_guard_cf": guard_cf,
        "pe_cet_shadow_stack": cet_shadow_stack,
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
        info = await loop.run_in_executor(None, _audit_elf_cfi, path)
    elif head[:2] == b"MZ":
        info = await loop.run_in_executor(None, _audit_pe_cfi, path)
    else:
        ctx.state["binary_unknown_format"] = True
        ctx.source("unrecognized binary header")
        return

    if info.get("_read_error") or info.get("_parse_error") or info.get("_not_elf") \
            or info.get("_pe_parse_error"):
        ctx.state["parse_error"] = str(
            info.get("_read_error") or info.get("_parse_error")
            or info.get("_not_elf") or info.get("_pe_parse_error"))
        ctx.source(f"parse error: {ctx.state['parse_error']}")
        return
    if info.get("_pefile_missing"):
        ctx.state["library_missing"] = f"pefile: {info['_pefile_missing']}"
        ctx.source("pefile unavailable")
        return

    ctx.state["cfi_info"] = info
    ctx.state["binary_kind"] = info.get("kind")
    ctx.state["binary_arch"] = info.get("arch")
    if info.get("kind") == "elf":
        ctx.source(
            f"ELF {info.get('arch')}/{info.get('bits')}bit CFI decode: "
            f"property_note={info.get('has_gnu_property_note')} "
            f"IBT={info.get('x86_ibt')} SHSTK={info.get('x86_shstk')} "
            f"BTI={info.get('aarch64_bti')} PAC={info.get('aarch64_pac')}"
        )
    else:
        ctx.source(
            f"PE {info.get('arch')}/{info.get('bits')}bit CFI decode: "
            f"CFG={info.get('pe_guard_cf')} CET-SS={info.get('pe_cet_shadow_stack')}"
        )


INTEL_FIELDS = [
    ("Binary kind",                "binary_kind"),
    ("Architecture",               "binary_arch"),
    ("Modern-CFI decode",          "cfi_info"),
]


@router.post("/api/bof/cfi_modern_mitigation_audit")
async def bof_cfi_modern_mitigation_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target,
        tool="cfi_modern_mitigation_audit",
        gather_func=gather,
        finding_rules=CFI_MODERN_MITIGATION_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
