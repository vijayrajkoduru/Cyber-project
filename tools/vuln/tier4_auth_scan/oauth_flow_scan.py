"""OAuth flow scan. VL-METHOD Wave 4.

Refactored 2026-06-09 to MethodologyScanner. Verify refetches the OIDC config
endpoint - if the same issue (alg=none / no S256 / etc.) appears in the
refetched config JSON, finding is CONFIRMED. Stable config = real misconfig;
flapping config = SUSPECTED.
"""
import json
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import probe_url_async, http_get_async

router = APIRouter()

OIDC_PATH = "/.well-known/openid-configuration"


def _audit(cfg):
    issues = []
    pkce = cfg.get("code_challenge_methods_supported") or []
    if "S256" not in pkce:
        issues.append({"sev": "HIGH", "kind": "no-s256",
                       "issue": f"PKCE S256 not advertised (got: {pkce or 'none'})"})
    if "none" in (cfg.get("id_token_signing_alg_values_supported") or []):
        issues.append({"sev": "CRITICAL", "kind": "alg-none",
                       "issue": "alg=none in id_token_signing_alg_values_supported"})
    algs = cfg.get("id_token_signing_alg_values_supported") or []
    if algs == ["HS256"]:
        issues.append({"sev": "MEDIUM", "kind": "hs256-only",
                       "issue": "Only HS256 advertised (no asymmetric algorithms)"})
    if not cfg.get("revocation_endpoint"):
        issues.append({"sev": "LOW", "kind": "no-revocation",
                       "issue": "No revocation_endpoint advertised"})
    return issues


async def _fetch_cfg(base_url):
    r = await http_get_async(f"{base_url}{OIDC_PATH}", timeout=8, read=20000)
    if not r or r.get("status") != 200: return None
    try:
        return json.loads(r.get("body", ""))
    except Exception:
        return None


class OauthFlowScan(MethodologyScanner):
    name = "oauth_flow_scan"

    async def pre_flight(self, ctx):
        base_url, base = await probe_url_async(str(ctx.host), "/")
        if not base:
            ctx.state["tested"] = 0
            ctx.state["skipped_reason"] = "Target unreachable"
            return False
        ctx.source("http")
        ctx.state["tested"] = 1
        ctx.state["base_url"] = base_url
        return True

    async def fingerprint(self, ctx):
        # OIDC issuer IS the fingerprint
        cfg = await _fetch_cfg(ctx.state["base_url"])
        ctx.state["oidc_config_found"] = bool(cfg)
        ctx.state["oidc_config_parsable"] = bool(cfg)
        if cfg:
            ctx.state["oauth_issuer"] = cfg.get("issuer")
            ctx.state["oauth_pkce_methods"] = cfg.get("code_challenge_methods_supported") or []
            ctx.state["oauth_signing_algs"] = cfg.get("id_token_signing_alg_values_supported") or []
            ctx.state["fingerprint"] = {
                "issuer": (cfg.get("issuer") or "")[:120],
            }

    async def quick_probe(self, ctx):
        cfg = await _fetch_cfg(ctx.state["base_url"])
        if not cfg:
            ctx.state["quick_hits"] = []
            return []
        issues = _audit(cfg)
        ctx.state["oauth_issues"] = issues
        ctx.state["quick_hits"] = issues
        return [dict(i) for i in issues]

    async def deep_scan(self, ctx):
        # OIDC config has a single source - no deeper paths to scan
        return []

    async def verify(self, ctx, finding):
        cfg = await _fetch_cfg(ctx.state["base_url"])
        if not cfg:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "refetch-config-failed"
            return finding
        issues2 = _audit(cfg)
        if any(i["kind"] == finding["kind"] for i in issues2):
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "refetch-issue-stable"
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "refetch-issue-gone"
        return finding


def _bucket(s, sev_pred, name, sev, cvss, cwe, remediation):
    verified = s.get("methodology_findings") or []
    matched = [f for f in verified if sev_pred(f.get("sev")) and f.get("confidence") == "CONFIRMED"]
    if not matched: return None
    return {"name": name, "severity": sev, "cvss": cvss, "cwe": cwe,
            "evidence": "; ".join(i["issue"] for i in matched),
            "remediation": remediation}


def _r_crit(s): return _bucket(s, lambda x: x == "CRITICAL",
                                 "OAuth/OIDC allows alg=none (CONFIRMED)",
                                 "CRITICAL", 9.8, "CWE-347",
                                 "Remove 'none' from id_token_signing_alg_values_supported. Pin RS256/ES256.")
def _r_high(s): return _bucket(s, lambda x: x == "HIGH",
                                 "OAuth/OIDC missing PKCE S256 (CONFIRMED)",
                                 "HIGH", 7.5, "CWE-352",
                                 "Advertise + require S256 PKCE for all public clients per OAuth 2.1 BCP.")
def _r_med(s): return _bucket(s, lambda x: x in ("MEDIUM", "LOW"),
                                "OAuth/OIDC hygiene (CONFIRMED)",
                                "MEDIUM", 4.3, "CWE-613",
                                "Support asymmetric signing + token revocation endpoint.")


FINDING_RULES = [_r_crit, _r_high, _r_med]
INTEL_FIELDS = [
    ("OIDC config found", "oidc_config_found"),
    ("Issuer", "oauth_issuer"),
    ("PKCE methods", "oauth_pkce_methods"),
    ("Signing algs", "oauth_signing_algs"),
    ("Quick-probe hits", "quick_hits"),
    ("Verified findings", "methodology_findings"),
    ("Stage timings (ms)", "stage_timings"),
]


@router.post("/api/vuln/oauth_flow_scan")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = OauthFlowScan()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
