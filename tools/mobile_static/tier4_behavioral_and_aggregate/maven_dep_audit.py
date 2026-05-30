"""maven_dep_audit — extract bundled dependency inventory from APK/IPA.

Mobile apps bundle their dependency tree. APK META-INF often contains
maven .properties + .pom fragments + dependency-info markers from
Gradle. IPA contains CocoaPods Podfile.lock fragments. This scanner
inventories what 3rd-party libraries are loaded, useful for CVE matching
+ supply-chain risk assessment.

MASVS-CODE-2 / MSTG-CODE-5.
"""
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.maven_dep_audit_findings import \
    MAVEN_DEP_AUDIT_FINDING_RULES

router = APIRouter()


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["maven_dep_audit_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["maven_dep_audit_error"] = str(e); return

    deps = set()  # (group_id, artifact_id, version) tuples as strings
    sources_seen = []

    # 1. META-INF/maven/*.properties → groupId=, artifactId=, version=
    for f in unpacked.rglob("*.properties"):
        if "META-INF" not in str(f) and "maven" not in str(f).lower(): continue
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")[:50_000]
        except Exception: continue
        g = re.search(r"^groupId=(.+)$", content, re.MULTILINE)
        a = re.search(r"^artifactId=(.+)$", content, re.MULTILINE)
        v = re.search(r"^version=(.+)$", content, re.MULTILINE)
        if g and a and v:
            deps.add(f"{g.group(1).strip()}:{a.group(1).strip()}:{v.group(1).strip()}")
            sources_seen.append("maven-properties")

    # 2. META-INF/com.android.tools/proguard/r8-from-* or .version files
    for f in unpacked.rglob("*.version"):
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")[:1000]
        except Exception: continue
        ver = content.strip().split("\n")[0]
        name = f.stem
        if ver and len(ver) < 60:
            deps.add(f"{name}:{ver}")
            sources_seen.append("version-file")

    # 3. IPA: Podfile.lock fragments / Frameworks/*
    for f in unpacked.rglob("Frameworks"):
        if not f.is_dir(): continue
        for sub in f.iterdir():
            if sub.is_dir() and sub.suffix == ".framework":
                deps.add(f"ios-framework:{sub.stem}")
                sources_seen.append("ios-framework")

    # 4. classes.dex prefix-based detection (fallback / cross-check)
    # Already covered by tracker_sdk_audit / third_party_sdk_audit — skip here

    deps_list = sorted(deps)
    ctx.state["dependencies"] = deps_list
    ctx.state["maven_dep_audit_total"] = len(deps_list)
    ctx.state["sources_used"] = list(set(sources_seen))
    ctx.source(f"{len(deps_list)} deps via {set(sources_seen)}")


INTEL_FIELDS = [
    ("Dependencies catalogued", "maven_dep_audit_total"),
    ("Sources used",            "sources_used"),
]


@router.post("/api/mobile_static/maven_dep_audit")
async def mobile_static_maven_dep_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="maven_dep_audit",
        gather_func=gather,
        finding_rules=MAVEN_DEP_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
