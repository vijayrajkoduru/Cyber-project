"""prototype_pollution_test - SAFE advisory-by-design probe (playbook §5 #44 + §7 #64).

VulnusLab is a Vulnerability Assessment platform (VA), NOT a penetration-testing
tool. Confirming prototype pollution requires SENDING __proto__/constructor
pollution payloads (e.g. {"__proto__":{"isAdmin":true}}) and observing whether
the runtime is contaminated across requests. That is active exploitation: it
mutates the target's shared state, can escalate privileges, and can crash the
process / affect other users. It is OUT OF SCOPE and is NOT performed here.

This probe is READ-ONLY: it fetches the page once and fingerprints whether any
prototype-pollution-prone JavaScript libraries are loaded (lodash, jQuery
$.extend, hoek, minimist, deep-merge helpers). It NEVER sends a pollution
payload. The result is an INFO advisory-by-design recommending manual
verification under an authorized engagement.
"""
from __future__ import annotations
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.prototype_pollution_test_findings import (
    PROTOTYPE_POLLUTION_TEST_FINDING_RULES,
)

router = APIRouter()


class PrototypePollutionRequest(ScanRequest):
    options: Optional[dict] = None


# Read-only fingerprints of prototype-pollution-prone client libraries. Their
# mere presence is NOT a vulnerability — it only marks where a manual tester
# should focus. No pollution payloads are derived from or sent for these.
_PP_PRONE_LIB_SIGS = [
    "lodash", "jquery", "hoek", "minimist", "deep-extend",
    "defaultsdeep", "extend.js", "merge-deep",
]


async def gather(ctx: ScanContext):
    target = (ctx.host or "").strip()
    if not target:
        ctx.source("no-target")
        return
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    try:
        import httpx
    except ImportError:
        ctx.state["proto_pollution_error"] = "httpx not installed"
        ctx.source("httpx missing")
        return

    libs: list[str] = []
    page_ok = False
    try:
        async with httpx.AsyncClient(
            verify=False, timeout=15, follow_redirects=True,
            headers={"User-Agent": "VulnusLab/2.0", "Accept": "*/*"},
        ) as client:
            r = await client.get(target)            # read-only GET, no payloads
            page_ok = True
            blob = (r.text or "").lower()
            for sig in _PP_PRONE_LIB_SIGS:
                if sig in blob and sig not in libs:
                    libs.append(sig)
    except Exception as e:
        ctx.state["proto_pollution_error"] = (
            f"read-only fetch failed: {type(e).__name__}: {str(e)[:120]}"
        )
        ctx.source("fetch failed")
        return

    ctx.state["proto_pollution_target_url"] = target
    ctx.state["proto_pollution_page_loaded"] = page_ok
    ctx.state["proto_pollution_prone_libs"] = libs
    ctx.source(f"read-only advisory; {len(libs)} PP-prone lib signature(s) "
               f"observed; NO payloads sent")


INTEL_FIELDS = [
    ("Target URL",                  "proto_pollution_target_url"),
    ("Page fetched (read-only)",    "proto_pollution_page_loaded"),
    ("PP-prone libraries observed", "proto_pollution_prone_libs"),
]


@router.post("/api/client_side/prototype_pollution_test")
async def client_side_prototype_pollution_test(req: PrototypePollutionRequest,
                                                _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="prototype_pollution_test",
        gather_func=_gather_with_options,
        finding_rules=PROTOTYPE_POLLUTION_TEST_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
