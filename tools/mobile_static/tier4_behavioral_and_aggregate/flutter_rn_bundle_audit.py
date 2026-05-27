"""flutter_rn_bundle_audit — detect & inspect Flutter / React Native / Capacitor bundles."""
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.flutter_rn_bundle_audit_findings import (
    FLUTTER_RN_BUNDLE_AUDIT_FINDING_RULES,
)

router = APIRouter()

URL_RX = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,200}")
SECRET_RX = re.compile(
    r"\b(?:sk_live_|sk_test_|pk_live_|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|"
    r"ghp_[A-Za-z0-9]{30,}|xox[abp]-[A-Za-z0-9-]{20,}|eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{10,})"
)
BUNDLE_MAX_SCAN = 8 * 1024 * 1024


def _detect_framework(unpacked):
    out = {"framework": "native", "evidence": []}
    flutter_so = list(unpacked.glob("lib/*/libflutter.so"))
    app_so = list(unpacked.glob("lib/*/libapp.so"))
    if flutter_so:
        out["framework"] = "flutter"
        out["evidence"].append(str(flutter_so[0].relative_to(unpacked)))
        if app_so:
            out["libapp_so_size"] = app_so[0].stat().st_size
    rn_bundle = unpacked / "assets" / "index.android.bundle"
    if rn_bundle.is_file():
        out["framework"] = "react_native" if out["framework"] == "native" else out["framework"]
        out["evidence"].append("assets/index.android.bundle")
        out["rn_bundle"] = rn_bundle
        out["rn_bundle_size"] = rn_bundle.stat().st_size
    cap_cfg = unpacked / "assets" / "capacitor.config.json"
    cap_public = unpacked / "assets" / "public" / "index.html"
    if cap_cfg.is_file() or cap_public.is_file():
        out["framework"] = "capacitor" if out["framework"] == "native" else out["framework"]
        out["evidence"].append("capacitor markers")
    cordova = unpacked / "assets" / "www" / "cordova.js"
    if cordova.is_file():
        out["framework"] = "cordova" if out["framework"] == "native" else out["framework"]
        out["evidence"].append("assets/www/cordova.js")
    return out


def _scan_js_bundle(path):
    sz = path.stat().st_size
    out = {"size": sz, "urls": [], "secrets": []}
    try:
        with path.open("rb") as f:
            data = f.read(BUNDLE_MAX_SCAN)
    except OSError:
        return out
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()[:200]
    avg_len = (sum(len(l) for l in lines) / len(lines)) if lines else 0
    out["minified"] = avg_len > 300
    seen_u = set()
    for m in URL_RX.findall(text):
        if m not in seen_u and len(seen_u) < 30:
            seen_u.add(m)
            out["urls"].append(m)
    seen_s = set()
    for m in SECRET_RX.findall(text):
        if m not in seen_s and len(seen_s) < 10:
            seen_s.add(m)
            out["secrets"].append(m[:20] + "…")
    return out


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["flutter_rn_bundle_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["flutter_rn_bundle_audit_error"] = str(e)
        return

    fw = _detect_framework(unpacked)
    ctx.state["framework"] = fw["framework"]
    ctx.state["framework_evidence"] = "; ".join(fw["evidence"])

    findings_total = 0
    if fw["framework"] != "native":
        findings_total += 1

    rn_bundle = fw.get("rn_bundle")
    if rn_bundle is not None:
        scan = _scan_js_bundle(rn_bundle)
        ctx.state["bundle_size"] = scan.get("size")
        ctx.state["bundle_minified"] = bool(scan.get("minified"))
        ctx.state["bundle_urls"] = scan.get("urls") or []
        ctx.state["bundle_secrets"] = scan.get("secrets") or []
        if not scan.get("minified"):
            findings_total += 1
        if scan.get("secrets"):
            findings_total += len(scan["secrets"])

    if fw["framework"] == "flutter":
        ctx.state["flutter_libapp_size"] = fw.get("libapp_so_size")

    ctx.state["flutter_rn_bundle_audit_total"] = findings_total
    ctx.source(f"binary scan — {fw['framework']}")


INTEL_FIELDS = [
    ("Cross-platform framework", "framework"),
    ("Findings", "flutter_rn_bundle_audit_total"),
]


@router.post("/api/mobile_static/flutter_rn_bundle_audit")
async def mobile_static_flutter_rn_bundle_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="flutter_rn_bundle_audit",
        gather_func=gather,
        finding_rules=FLUTTER_RN_BUNDLE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
