"""network_lib_inventory — fingerprint network / HTTP libraries used,
with version extraction from META-INF + class signatures. Feeds into
manual CVE lookup (e.g. OkHttp <4.9.2 = CVE-2021-0341). Helps customer
prioritize dependency updates."""
from __future__ import annotations
import re
import zipfile
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.network_lib_inventory_findings import NETWORK_LIB_INVENTORY_FINDING_RULES

router = APIRouter()

LIB_MARKERS = {
    "OkHttp":              ["okhttp3/OkHttpClient", "Lokhttp3/"],
    "Retrofit":            ["retrofit2/Retrofit", "retrofit2/Call;"],
    "Volley":              ["com/android/volley/Request"],
    "Apollo GraphQL":      ["com/apollographql/apollo3"],
    "Cronet (Chromium)":   ["org/chromium/net/CronetEngine"],
    "Ktor":                ["io/ktor/client"],
    "Apache HttpClient":   ["org/apache/http/client/HttpClient"],
    "AsyncHttpClient":     ["com/loopj/android/http"],
    "Glide (image net)":   ["com/bumptech/glide/Glide"],
    "Picasso":             ["com/squareup/picasso/Picasso"],
    "Fuel (Kotlin)":       ["com/github/kittinunf/fuel"],
}
# Version markers — substrings inside class files / properties
VERSION_HINTS = {
    "OkHttp":    re.compile(r'okhttp/([0-9]+\.[0-9]+\.[0-9]+)'),
    "Retrofit":  re.compile(r'retrofit/([0-9]+\.[0-9]+\.[0-9]+)'),
}
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["network_lib_inventory_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["network_lib_inventory_error"] = str(e)
        return

    libs_found = {}
    versions = {}
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1
        for lib, markers in LIB_MARKERS.items():
            for m in markers:
                if m in txt:
                    libs_found.setdefault(lib, [])
                    if p.name not in libs_found[lib] and len(libs_found[lib]) < 3:
                        libs_found[lib].append(p.name)
                    break
        for lib, regex in VERSION_HINTS.items():
            for vm in regex.finditer(txt):
                if lib not in versions:
                    versions[lib] = vm.group(1)

    # Try to extract version from APK META-INF / classes.dex string table
    try:
        with zipfile.ZipFile(apk) as zf:
            for name in zf.namelist():
                if name.endswith(".properties") or "version" in name.lower():
                    try:
                        data = zf.read(name).decode("utf-8", errors="ignore")
                        for lib, regex in VERSION_HINTS.items():
                            m = regex.search(data)
                            if m and lib not in versions:
                                versions[lib] = m.group(1)
                    except Exception:
                        pass
    except Exception:
        pass

    ctx.state["network_libraries"] = libs_found
    ctx.state["library_versions"] = versions
    ctx.state["files_scanned"] = files_scanned
    ctx.state["network_lib_inventory_total"] = 1 if libs_found else 0
    ctx.source(f"{files_scanned} smali files + META-INF")


INTEL_FIELDS = [
    ("Network libraries detected", "network_libraries"),
    ("Versions (best-effort extraction)", "library_versions"),
]


@router.post("/api/mobile_network/network_lib_inventory")
async def mobile_network_network_lib_inventory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="network_lib_inventory",
        gather_func=gather,
        finding_rules=NETWORK_LIB_INVENTORY_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
