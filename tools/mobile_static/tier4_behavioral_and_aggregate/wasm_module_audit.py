"""wasm_module_audit — detect WebAssembly modules embedded in mobile apps."""
import struct
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.wasm_module_audit_findings import (
    WASM_MODULE_AUDIT_FINDING_RULES,
)

router = APIRouter()

WASM_MAGIC = b"\x00asm"
SECTION_NAMES = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table",
    5: "memory", 6: "global", 7: "export", 8: "start", 9: "element",
    10: "code", 11: "data", 12: "datacount",
}


def _read_uleb128(buf, pos):
    val = 0
    shift = 0
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return val, pos
        shift += 7
        if shift > 63:
            return val, pos
    return val, pos


def _parse_wasm(path):
    out = {"path": str(path), "size": path.stat().st_size, "valid": False}
    try:
        with path.open("rb") as f:
            data = f.read(8 * 1024 * 1024)
    except OSError:
        return out
    if not data.startswith(WASM_MAGIC):
        return out
    if len(data) < 8:
        return out
    out["valid"] = True
    out["version"] = struct.unpack("<I", data[4:8])[0]
    pos = 8
    sections, imports = [], []
    exports_count = 0
    has_dwarf = False
    while pos < len(data):
        if pos >= len(data):
            break
        sec_id = data[pos]
        pos += 1
        sec_size, pos = _read_uleb128(data, pos)
        sec_end = min(pos + sec_size, len(data))
        sections.append(SECTION_NAMES.get(sec_id, f"id{sec_id}"))
        if sec_id == 0 and pos < sec_end:
            name_len, pos = _read_uleb128(data, pos)
            try:
                custom_name = data[pos:pos + name_len].decode("utf-8", "replace")
                if custom_name.startswith(".debug"):
                    has_dwarf = True
            except Exception:
                pass
            pos = sec_end
            continue
        if sec_id == 2:
            count, pos = _read_uleb128(data, pos)
            for _ in range(min(count, 200)):
                mod_len, pos = _read_uleb128(data, pos)
                mod = data[pos:pos + mod_len].decode("utf-8", "replace")
                pos += mod_len
                fn_len, pos = _read_uleb128(data, pos)
                fn = data[pos:pos + fn_len].decode("utf-8", "replace")
                pos += fn_len
                if pos < len(data):
                    pos += 1
                if len(imports) < 50:
                    imports.append(f"{mod}.{fn}")
                if pos < len(data):
                    _, pos = _read_uleb128(data, pos)
            pos = sec_end
            continue
        if sec_id == 7:
            count, pos = _read_uleb128(data, pos)
            exports_count = count
            pos = sec_end
            continue
        pos = sec_end
    out["sections"] = list(dict.fromkeys(sections))
    out["imports"] = imports
    out["exports_count"] = exports_count
    out["has_dwarf"] = has_dwarf
    return out


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["wasm_module_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["wasm_module_audit_error"] = str(e)
        return

    wasms = list(unpacked.rglob("*.wasm"))
    if not wasms:
        ctx.state["wasm_module_audit_total"] = 0
        ctx.source("no-wasm")
        return

    modules = []
    for p in wasms[:10]:
        info = _parse_wasm(p)
        info["rel_path"] = str(p.relative_to(unpacked))
        modules.append(info)

    ctx.state["wasm_modules"] = modules
    ctx.state["wasm_module_audit_total"] = len([m for m in modules if m.get("valid")])
    ctx.source("wasm headers + sections")


INTEL_FIELDS = [("WASM modules", "wasm_module_audit_total")]


@router.post("/api/mobile_static/wasm_module_audit")
async def mobile_static_wasm_module_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="wasm_module_audit",
        gather_func=gather,
        finding_rules=WASM_MODULE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
