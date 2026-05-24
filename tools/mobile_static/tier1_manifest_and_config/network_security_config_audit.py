"""network_security_config_audit — Android network_security_config.xml audit."""
from pathlib import Path
from xml.etree import ElementTree as ET

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.network_security_config_audit_findings import NETWORK_SECURITY_CONFIG_AUDIT_FINDING_RULES

router = APIRouter()


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["network_security_config_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["network_security_config_audit_error"] = str(e)
        return

    cfg_files = list(unpacked.rglob("network_security_config.xml"))
    if not cfg_files:
        ctx.state["network_security_config_audit_total"] = 0
        ctx.source("no-network-config")
        return

    issues = []
    for cfg in cfg_files[:5]:
        try:
            root = ET.parse(str(cfg)).getroot()
        except ET.ParseError:
            continue

        # cleartextTrafficPermitted on <base-config> or <domain-config>
        base = root.find("base-config")
        if base is not None and base.get("cleartextTrafficPermitted") == "true":
            issues.append({"file": cfg.name, "flag": "cleartextTrafficPermitted",
                            "scope": "base-config"})
        for dc in root.findall("domain-config"):
            if dc.get("cleartextTrafficPermitted") == "true":
                doms = [d.text for d in dc.findall("domain")]
                issues.append({"file": cfg.name, "flag": "cleartextTrafficPermitted",
                                "scope": "domain-config",
                                "domains": doms})
            # trust-anchors with user CAs allowed
            for ta in dc.findall("trust-anchors"):
                for cert in ta.findall("certificates"):
                    if cert.get("src") == "user":
                        issues.append({"file": cfg.name, "flag": "user-trust-anchors",
                                        "domains": [d.text for d in dc.findall("domain")]})

    ctx.state["nsc_issues"] = issues
    ctx.state["network_security_config_audit_total"] = len(issues)
    ctx.source("network_security_config.xml")


INTEL_FIELDS = [
    ("NSC issues", "network_security_config_audit_total"),
]


@router.post("/api/mobile_static/network_security_config_audit")
async def mobile_static_network_security_config_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="network_security_config_audit",
        gather_func=gather,
        finding_rules=NETWORK_SECURITY_CONFIG_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
