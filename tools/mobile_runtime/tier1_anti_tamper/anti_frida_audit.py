"""anti_frida_audit — detect anti-Frida defenses (port 27042 scan,
/data/local/tmp/frida-server file checks, frida-agent string scans,
re.frida.server, linjector helpers). Most apps lack ANY of these, making
Frida hooking trivial."""
from __future__ import annotations
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.anti_frida_audit_findings import ANTI_FRIDA_AUDIT_FINDING_RULES

router = APIRouter()

ANTI_FRIDA_MARKERS = {
    "Frida default port 27042":      ['"27042"', " 27042 ", ":27042"],
    "frida-server filesystem check": ['"frida-server"', '"/data/local/tmp/frida-server"', '"/data/local/tmp/frida"'],
    "frida-agent string scan":       ['"frida-agent"', '"frida-gadget"', '"libfrida"'],
    "re.frida.server marker":        ['"re.frida.server"', '"re-frida-server"'],
    "linjector helper detection":    ["linjector-helper-32", "linjector-helper-64"],
    "/proc/self/maps inspection":    ['"/proc/self/maps"', '"/proc/self/status"'],
    "pthread_attr_get_np":           ["pthread_attr_get_np", "pthread_getattr_np"],
}
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["anti_frida_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["anti_frida_audit_error"] = str(e)
        return

    mechanisms = {}
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1
        for mech_name, markers in ANTI_FRIDA_MARKERS.items():
            for m in markers:
                if m in txt:
                    mechanisms.setdefault(mech_name, [])
                    if len(mechanisms[mech_name]) < 5 and p.name not in mechanisms[mech_name]:
                        mechanisms[mech_name].append(p.name)
                    break

    # Also scan native libs for frida strings
    native_anti_frida = []
    for so in (unpacked / "lib").rglob("*.so"):
        try:
            data = so.read_bytes()
        except OSError:
            continue
        if b"frida-agent" in data or b"frida-server" in data or b"27042" in data:
            native_anti_frida.append(so.name)
        if len(native_anti_frida) >= 20:
            break

    ctx.state["anti_frida_mechanisms"] = mechanisms
    ctx.state["native_anti_frida"] = native_anti_frida
    ctx.state["files_scanned"] = files_scanned
    ctx.state["anti_frida_audit_total"] = len(mechanisms) + (1 if native_anti_frida else 0)
    ctx.source(f"{files_scanned} smali files")


INTEL_FIELDS = [
    ("Java anti-Frida markers", "anti_frida_mechanisms"),
    ("Native libs with anti-Frida strings", "native_anti_frida"),
]


@router.post("/api/mobile_runtime/anti_frida_audit")
async def mobile_runtime_anti_frida_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="anti_frida_audit",
        gather_func=gather,
        finding_rules=ANTI_FRIDA_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
