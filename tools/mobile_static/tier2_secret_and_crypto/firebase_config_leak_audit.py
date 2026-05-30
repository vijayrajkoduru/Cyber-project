"""firebase_config_leak_audit — google-services.json + Firebase config leak.

Firebase Android apps bundle google-services.json which contains
google_api_key, project_id, project_number, mobile_sdk_app_id. By design
these aren't 'secret' BUT a misconfigured Firebase project (open Realtime
DB, open Firestore rules, open Cloud Storage) means anyone with these
fields can read/write your DB. Also flags client_secret-shaped strings
that should NEVER be bundled.
"""
import json
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.firebase_config_leak_audit_findings import \
    FIREBASE_CONFIG_LEAK_AUDIT_FINDING_RULES

router = APIRouter()


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["firebase_config_leak_audit_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["firebase_config_leak_audit_error"] = str(e); return

    # Search for google-services.json (Android) or GoogleService-Info.plist (iOS)
    found = []
    project_ids = []
    api_keys = []
    db_urls = []
    for f in unpacked.rglob("*"):
        if not f.is_file(): continue
        name = f.name.lower()
        if name == "google-services.json":
            try:
                data = json.loads(f.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                continue
            found.append({"path": f.relative_to(unpacked).as_posix(),
                          "type": "android"})
            for client in data.get("client", []):
                api_key_obj = client.get("api_key", [])
                if isinstance(api_key_obj, list):
                    for k in api_key_obj:
                        if k.get("current_key"):
                            api_keys.append(k["current_key"][:40])
                proj = data.get("project_info", {})
                if proj.get("project_id"):
                    project_ids.append(proj["project_id"])
                if proj.get("firebase_url"):
                    db_urls.append(proj["firebase_url"])
        elif name == "googleservice-info.plist":
            found.append({"path": f.relative_to(unpacked).as_posix(),
                          "type": "ios"})
            # Plist is binary or XML — extract key strings via grep
            try:
                content = f.read_bytes()[:200_000]
                # Look for API key pattern (AIza...)
                import re
                for m in re.finditer(rb"AIza[0-9A-Za-z_-]{35}", content):
                    api_keys.append(m.group(0).decode())
                for m in re.finditer(rb"PROJECT_ID[^a-zA-Z0-9_]+([a-zA-Z0-9_-]{4,40})",
                                       content):
                    project_ids.append(m.group(1).decode())
            except Exception:
                pass

    ctx.state["firebase_configs_found"] = found
    ctx.state["project_ids"] = list(set(project_ids))
    ctx.state["api_keys"] = list(set(api_keys))
    ctx.state["firebase_db_urls"] = list(set(db_urls))
    ctx.state["firebase_config_leak_audit_total"] = len(found)
    ctx.source(f"{len(found)} Firebase config file(s) found")


INTEL_FIELDS = [
    ("Firebase configs",  "firebase_configs_found"),
    ("Project IDs",       "project_ids"),
    ("API keys",          "api_keys"),
    ("Realtime DB URLs",  "firebase_db_urls"),
]


@router.post("/api/mobile_static/firebase_config_leak_audit")
async def mobile_static_firebase_config_leak_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="firebase_config_leak_audit",
        gather_func=gather,
        finding_rules=FIREBASE_CONFIG_LEAK_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
