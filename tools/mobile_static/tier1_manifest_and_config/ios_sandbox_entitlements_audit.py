"""ios_sandbox_entitlements_audit — iOS App Sandbox entitlements audit.

Apple's App Sandbox restricts what an app can do. Entitlements (in
embedded.provisioningprofile / *.entitlements) GRANT additional
capabilities. Risky entitlements:
  - com.apple.security.network.server (incoming sockets)
  - com.apple.security.cs.allow-jit (JIT compilation — bypass W^X)
  - com.apple.security.cs.disable-library-validation (load unsigned dylibs)
  - com.apple.developer.networking.HotspotConfiguration (silent Wi-Fi)
  - keychain-access-groups (share creds with other apps)

MASVS-PLATFORM-1 iOS.
"""
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.ios_sandbox_entitlements_audit_findings import \
    IOS_SANDBOX_ENTITLEMENTS_AUDIT_FINDING_RULES

router = APIRouter()

RISKY_ENTITLEMENTS = {
    "com.apple.security.cs.allow-jit":                        "JIT compilation enabled",
    "com.apple.security.cs.allow-unsigned-executable-memory": "Unsigned exec memory allowed",
    "com.apple.security.cs.disable-library-validation":       "Library validation disabled",
    "com.apple.security.cs.disable-executable-page-protection":"Page protection disabled",
    "com.apple.security.cs.allow-dyld-environment-variables": "DYLD env vars allowed",
    "com.apple.security.get-task-allow":                       "Debugger attach allowed (DEV-ONLY)",
    "com.apple.developer.networking.HotspotConfiguration":     "Silent Wi-Fi config",
    "com.apple.developer.networking.networkextension":         "VPN/Network extension",
}


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["ios_sandbox_entitlements_audit_total"] = 0
        ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["ios_sandbox_entitlements_audit_error"] = str(e); return

    # Find .entitlements files OR embedded.provisioningprofile
    risky_found = []
    sources_seen = []
    for f in list(unpacked.rglob("*.entitlements")) + \
              list(unpacked.rglob("embedded.provisioningprofile")):
        try: content = f.read_bytes()[:200000]
        except Exception: continue
        sources_seen.append(f.relative_to(unpacked).as_posix())
        for key, desc in RISKY_ENTITLEMENTS.items():
            if key.encode() in content:
                risky_found.append({"key": key, "desc": desc,
                                      "file": f.relative_to(unpacked).as_posix()})

    if not sources_seen:
        ctx.state["ios_sandbox_entitlements_audit_total"] = 0
        ctx.state["entitlement_sources"] = []
        ctx.source("no-entitlements-file (not iOS or stripped)"); return

    ctx.state["risky_entitlements"] = risky_found
    ctx.state["entitlement_sources"] = sources_seen
    ctx.state["ios_sandbox_entitlements_audit_total"] = len(risky_found)
    ctx.source(f"{len(sources_seen)} entitlement files, {len(risky_found)} risky")


INTEL_FIELDS = [
    ("Risky entitlements",  "risky_entitlements"),
    ("Sources scanned",     "entitlement_sources"),
]


@router.post("/api/mobile_static/ios_sandbox_entitlements_audit")
async def mobile_static_ios_sandbox_entitlements_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="ios_sandbox_entitlements_audit", gather_func=gather,
        finding_rules=IOS_SANDBOX_ENTITLEMENTS_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
