"""dangerous_function_detect - audit binary for calls to unsafe libc primitives.

Disassembles the binary with capstone (for the .text section bytes) and
walks the symbol table via pwntools ELF / pefile to find every CALL into
a known-bad function:

    strcpy, strcat, gets, sprintf, vsprintf, scanf (with %s), system,
    execve/execl/execlp/execv/execvp, popen, memcpy (when size is non-immediate)

Each call site is reported MEDIUM (CWE-120 / CWE-242 / CWE-78).  The list
is empirical: we cross-reference the imports + PLT against this list, then
locate every CALL instruction targeting one of those PLT stubs and record
the caller-symbol + offset.
"""
from __future__ import annotations
import asyncio
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.dangerous_function_detect_findings import (
    DANGEROUS_FUNCTION_DETECT_FINDING_RULES,
)

router = APIRouter()
MAX_CALL_SITES = 200    # cap for PDF readability
MAX_BINARY_SIZE_MB = 256

# Dangerous libc primitives + their CWE bucket.
# scanf shows up as ambiguous (only bad with "%s" format) - we still flag it
# but tag severity LOW; the rule layer escalates if the binary also contains
# the string "%s\x00" (heuristic).
DANGEROUS_FUNCS = {
    "gets":      ("CWE-242", "always-unsafe; removed from C11"),
    "strcpy":    ("CWE-120", "no bounds check"),
    "strcat":    ("CWE-120", "no bounds check"),
    "sprintf":   ("CWE-120", "no destination-size argument"),
    "vsprintf":  ("CWE-120", "no destination-size argument"),
    "scanf":     ("CWE-120", "unsafe if format contains %s without width"),
    "fscanf":    ("CWE-120", "unsafe if format contains %s without width"),
    "vscanf":    ("CWE-120", "unsafe if format contains %s without width"),
    "system":    ("CWE-78",  "shell command injection if any argv element is attacker-controlled"),
    "popen":     ("CWE-78",  "shell command injection if any argv element is attacker-controlled"),
    "execl":     ("CWE-78",  "exec family - command injection risk"),
    "execlp":    ("CWE-78",  "exec family - command injection risk"),
    "execle":    ("CWE-78",  "exec family - command injection risk"),
    "execv":     ("CWE-78",  "exec family - command injection risk"),
    "execvp":    ("CWE-78",  "exec family - command injection risk"),
    "execve":    ("CWE-78",  "exec family - command injection risk"),
    "memcpy":    ("CWE-120", "unsafe when length is non-constant attacker-controlled"),
    "strncpy":   ("CWE-170", "does NOT null-terminate when source >= dest length"),
}


class DangerousFunctionDetectRequest(ScanRequest):
    options: Optional[dict] = None


def _normalize(name: str) -> str:
    """Strip @plt suffix + glibc versioning + leading underscores so 'strcpy@plt',
    'strcpy@@GLIBC_2.2.5' and '__strcpy_chk' all collapse to 'strcpy'."""
    if not name:
        return ""
    n = name
    for suffix in ("@plt", "@PLT", "@@GLIBC_2.2.5", "@@GLIBC_2.4", "@@GLIBC_2.17"):
        if n.endswith(suffix):
            n = n[: -len(suffix)]
    if "@" in n:
        n = n.split("@", 1)[0]
    if n.startswith("__") and n.endswith("_chk"):
        n = n[2:-4]  # __strcpy_chk -> strcpy (the chk variant is the SAFE one)
        return f"safe_{n}"
    return n.lstrip("_")


def _scan_elf(path: Path) -> dict:
    """Walk ELF symbols + disasm with capstone to find CALL/JMP to dangerous PLT stubs."""
    try:
        from pwn import ELF, context
        context.log_level = "error"
    except ImportError as e:
        return {"_pwntools_missing": str(e)}
    try:
        from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_32, CS_MODE_64, CS_MODE_ARM
    except ImportError as e:
        return {"_capstone_missing": str(e)}

    try:
        elf = ELF(str(path), checksec=False)
    except Exception as e:
        return {"_elf_parse_error": str(e)}

    arch_map = {
        ("i386",   32): (CS_ARCH_X86, CS_MODE_32),
        ("amd64",  64): (CS_ARCH_X86, CS_MODE_64),
        ("x86_64", 64): (CS_ARCH_X86, CS_MODE_64),
        ("arm",    32): (CS_ARCH_ARM, CS_MODE_ARM),
        ("aarch64",64): (CS_ARCH_ARM64, CS_MODE_ARM),
    }
    key = (elf.arch, elf.bits)
    if key not in arch_map:
        return {"_unsupported_arch": f"{elf.arch}/{elf.bits}"}
    cs_arch, cs_mode = arch_map[key]
    md = Cs(cs_arch, cs_mode)
    md.detail = False

    # Build PLT address -> dangerous function name map
    plt_lookup: dict[int, str] = {}
    has_chk_variants = []
    for sym_name, sym_addr in elf.symbols.items():
        if not isinstance(sym_name, str):
            continue
        base = _normalize(sym_name)
        if base.startswith("safe_"):
            has_chk_variants.append(base[5:])
            continue
        if base in DANGEROUS_FUNCS:
            try:
                plt_lookup[int(sym_addr)] = base
            except (TypeError, ValueError):
                pass

    # Reverse function map (addr -> function name) to attribute call sites
    func_table: list[tuple[int, str]] = []
    for sym_name, sym_addr in elf.symbols.items():
        if not isinstance(sym_name, str):
            continue
        try:
            func_table.append((int(sym_addr), sym_name))
        except (TypeError, ValueError):
            pass
    func_table.sort()

    def _caller_of(addr: int) -> str:
        # Binary-search the largest function-start <= addr
        lo, hi = 0, len(func_table) - 1
        best = ""
        while lo <= hi:
            mid = (lo + hi) // 2
            fa, fn = func_table[mid]
            if fa <= addr:
                best = fn
                lo = mid + 1
            else:
                hi = mid - 1
        return best or "(unknown)"

    # Disasm .text section, look for branches into PLT entries
    text_section = None
    try:
        text_section = elf.get_section_by_name(".text")
    except Exception:
        pass
    if text_section is None:
        return {"_no_text_section": True}

    try:
        text_bytes = text_section.data()
        text_addr = text_section.header.sh_addr
    except Exception as e:
        return {"_text_read_error": str(e)}

    call_sites: list[dict] = []
    # x86 CALL = E8 rel32 or FF /2 modrm; ARM = BL/BLX.  capstone's mnemonic check is enough.
    BRANCH_MNEMONICS = {"call", "jmp", "bl", "blx", "blr", "b"}

    counter = 0
    for ins in md.disasm(text_bytes, text_addr):
        counter += 1
        if counter > 5_000_000:
            break  # hard cap - never disasm more than 5M instructions
        if ins.mnemonic.lower() not in BRANCH_MNEMONICS:
            continue
        op = ins.op_str.strip().lower()
        # Try to parse the immediate target.  capstone gives e.g. "0x401050" or "#0x10078".
        target_addr = None
        try:
            tok = op.split(",")[0].strip().lstrip("#").lstrip("$")
            if tok.startswith("0x"):
                target_addr = int(tok, 16)
            elif tok.isdigit():
                target_addr = int(tok)
        except Exception:
            target_addr = None
        if target_addr is None:
            continue
        if target_addr in plt_lookup:
            func = plt_lookup[target_addr]
            if len(call_sites) >= MAX_CALL_SITES:
                continue
            call_sites.append({
                "callee":    func,
                "caller":    _caller_of(ins.address),
                "caller_offset": hex(ins.address),
                "cwe":       DANGEROUS_FUNCS[func][0],
                "why":       DANGEROUS_FUNCS[func][1],
            })

    # Group by callee for the report
    by_callee: dict[str, int] = {}
    for cs_ in call_sites:
        by_callee[cs_["callee"]] = by_callee.get(cs_["callee"], 0) + 1

    return {
        "kind": "elf",
        "arch": f"{elf.arch}/{elf.bits}bit",
        "dangerous_imports": sorted(by_callee.keys()),
        "call_sites":        call_sites,
        "calls_by_callee":   by_callee,
        "fortify_chk_used":  sorted(set(has_chk_variants)),
    }


def _scan_pe(path: Path) -> dict:
    """List dangerous imports from a PE Import Address Table.  No disasm
    yet (PE PLT-equivalent is the IAT, which capstone CAN walk but call-site
    attribution needs DIA SDK / dbghelp - we keep it simple for the starter)."""
    try:
        import pefile  # type: ignore
    except ImportError as e:
        return {"_pefile_missing": str(e)}
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories()
    except Exception as e:
        return {"_pe_parse_error": str(e)}

    imports: list[dict] = []
    found_names: set[str] = set()
    try:
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll = (entry.dll or b"").decode("utf-8", errors="ignore").lower()
            for imp in entry.imports:
                name = (imp.name or b"").decode("utf-8", errors="ignore")
                base = _normalize(name)
                if base.startswith("safe_"):
                    continue
                if base in DANGEROUS_FUNCS:
                    if base in found_names:
                        continue
                    found_names.add(base)
                    imports.append({
                        "callee": base,
                        "dll":    dll,
                        "cwe":    DANGEROUS_FUNCS[base][0],
                        "why":    DANGEROUS_FUNCS[base][1],
                    })
    except Exception as e:
        return {"_iat_walk_error": str(e)}

    # Windows CRT extras (lstrcpy, lstrcat, _mbscpy = same risk as strcpy)
    windows_extra_unsafe = {"lstrcpya", "lstrcpyw", "lstrcata", "lstrcatw",
                            "_mbscpy", "_mbscat"}
    try:
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            for imp in entry.imports:
                name = (imp.name or b"").decode("utf-8", errors="ignore").lower()
                if name in windows_extra_unsafe and name not in found_names:
                    found_names.add(name)
                    imports.append({
                        "callee": name,
                        "dll":    (entry.dll or b"").decode("utf-8", errors="ignore").lower(),
                        "cwe":    "CWE-120",
                        "why":    "Win32 narrow/wide string copy without bounds check",
                    })
    except Exception:
        pass

    return {
        "kind": "pe",
        "dangerous_imports": sorted([i["callee"] for i in imports]),
        "call_sites":        imports[:MAX_CALL_SITES],   # PE list IS the IAT, no per-call address
        "calls_by_callee":   {i["callee"]: 1 for i in imports},
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

    # Re-use the header sniff from binary_protection_audit
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError as e:
        ctx.state["binary_read_error"] = str(e)
        ctx.source(f"read error: {e}")
        return

    loop = asyncio.get_event_loop()
    if head[:4] == b"\x7fELF":
        info = await loop.run_in_executor(None, _scan_elf, path)
    elif head[:2] == b"MZ":
        info = await loop.run_in_executor(None, _scan_pe, path)
    else:
        ctx.state["binary_unknown_format"] = True
        ctx.source("unrecognized binary header")
        return

    for err_key in ("_pwntools_missing", "_capstone_missing", "_pefile_missing"):
        if info.get(err_key):
            ctx.state["library_missing"] = f"{err_key}: {info[err_key]}"
            ctx.source(f"library missing: {err_key}")
            return
    for err_key in ("_elf_parse_error", "_pe_parse_error", "_text_read_error",
                    "_iat_walk_error"):
        if info.get(err_key):
            ctx.state["parse_error"] = f"{err_key}: {info[err_key]}"
            ctx.source(f"parse error: {err_key}")
            return
    if info.get("_unsupported_arch"):
        ctx.state["unsupported_arch"] = info["_unsupported_arch"]
        ctx.source(f"unsupported architecture {info['_unsupported_arch']}")
        return
    if info.get("_no_text_section"):
        ctx.state["no_text_section"] = True
        ctx.source("no .text section in ELF")
        return

    ctx.state["binary_kind"]      = info.get("kind")
    ctx.state["binary_arch"]      = info.get("arch", "")
    ctx.state["dangerous_imports"] = info.get("dangerous_imports") or []
    ctx.state["call_sites"]       = info.get("call_sites") or []
    ctx.state["calls_by_callee"]  = info.get("calls_by_callee") or {}
    ctx.state["fortify_chk_used"] = info.get("fortify_chk_used") or []
    n_calls = sum((info.get("calls_by_callee") or {}).values())
    ctx.state["dangerous_call_total"] = n_calls
    ctx.source(
        f"capstone+pwntools/pefile: {len(info.get('dangerous_imports') or [])} dangerous "
        f"imports, {n_calls} call site(s)"
    )


INTEL_FIELDS = [
    ("Binary kind",              "binary_kind"),
    ("Architecture",             "binary_arch"),
    ("Dangerous imports",        "dangerous_imports"),
    ("Calls by callee",          "calls_by_callee"),
    ("Total dangerous calls",    "dangerous_call_total"),
    ("FORTIFY_SOURCE _chk used", "fortify_chk_used"),
    ("Call sites (sampled)",     "call_sites"),
]


@router.post("/api/bof/dangerous_function_detect")
async def bof_dangerous_function_detect(
    req: DangerousFunctionDetectRequest, _=Depends(verify_scan_quota)
):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="dangerous_function_detect",
        gather_func=_gather_with_options,
        finding_rules=DANGEROUS_FUNCTION_DETECT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
