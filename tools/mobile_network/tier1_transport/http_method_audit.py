"""http_method_audit — catalog HTTP methods the app uses from the client.
Anything beyond GET/POST/PUT/DELETE/PATCH/HEAD is unusual and worth a
manual look. TRACE/CONNECT/OPTIONS to non-CORS endpoints = SSRF-style
risk patterns. Helps customer narrow Burp testing scope."""
from __future__ import annotations
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.http_method_audit_findings import HTTP_METHOD_AUDIT_FINDING_RULES

router = APIRouter()

# Retrofit annotations + raw method literals + OkHttp .method()
METHOD_PATTERNS = [
    re.compile(r'@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\b'),
    re.compile(r'\.method\("([A-Z]{3,7})"'),
    re.compile(r'setRequestMethod\("([A-Z]{3,7})"'),
    re.compile(r'"X-HTTP-Method-Override"'),  # tunneling = sus
]
INTERESTING_METHODS = ("TRACE", "CONNECT", "OPTIONS", "PROPFIND", "MKCOL")
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["http_method_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["http_method_audit_error"] = str(e)
        return

    method_counts = {}
    method_override_files = []
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1

        for regex in METHOD_PATTERNS[:3]:
            for m in regex.finditer(txt):
                method = m.group(1).upper()
                method_counts[method] = method_counts.get(method, 0) + 1
        if METHOD_PATTERNS[3].search(txt):
            if p.name not in method_override_files and len(method_override_files) < 10:
                method_override_files.append(p.name)

    interesting = {m: c for m, c in method_counts.items() if m in INTERESTING_METHODS}

    ctx.state["http_method_counts"] = method_counts
    ctx.state["interesting_methods"] = interesting
    ctx.state["method_override_headers"] = method_override_files
    ctx.state["files_scanned"] = files_scanned
    ctx.state["http_method_audit_total"] = len(interesting) + (1 if method_override_files else 0)
    ctx.source(f"{files_scanned} smali files")


INTEL_FIELDS = [
    ("HTTP method usage counts", "http_method_counts"),
    ("Interesting methods (TRACE/CONNECT/OPTIONS)", "interesting_methods"),
    ("X-HTTP-Method-Override files", "method_override_headers"),
]


@router.post("/api/mobile_network/http_method_audit")
async def mobile_network_http_method_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="http_method_audit",
        gather_func=gather,
        finding_rules=HTTP_METHOD_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
