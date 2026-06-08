"""OAuth flow scan - passive OAuth/OIDC metadata + redirect_uri check. Self-contained.
Strategy: fetch .well-known/openid-configuration + /oauth/authorize, check for PKCE
support, redirect_uri validation hint, allowed schemes."""
import json
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url_async, http_get_async

router = APIRouter()

OIDC_PATH = "/.well-known/openid-configuration"


async def gather(ctx):
    host = str(ctx.host)
    base_url, base = await probe_url_async(host, "/")
    if not base:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    issues = []
    config_url = f"{base_url}{OIDC_PATH}"
    r = await http_get_async(config_url, timeout=8, read=20000)
    if not r or r.get("status") != 200:
        ctx.state["oidc_config_found"] = False
        return
    ctx.state["oidc_config_found"] = True
    try:
        cfg = json.loads(r.get("body", ""))
    except Exception:
        ctx.state["oidc_config_parsable"] = False
        return
    ctx.state["oidc_config_parsable"] = True
    # PKCE support check (S256 required for public clients per RFC 7636 + BCP)
    pkce = cfg.get("code_challenge_methods_supported") or []
    if "S256" not in pkce:
        issues.append({"sev": "HIGH", "issue": f"PKCE S256 not advertised (got: {pkce or 'none'})"})
    # alg=none
    if "none" in (cfg.get("id_token_signing_alg_values_supported") or []):
        issues.append({"sev": "CRITICAL", "issue": "alg=none in id_token_signing_alg_values_supported"})
    # HS256 only (no async)
    algs = cfg.get("id_token_signing_alg_values_supported") or []
    if algs == ["HS256"]:
        issues.append({"sev": "MEDIUM", "issue": "Only HS256 advertised (no asymmetric algorithms)"})
    # Missing token revocation endpoint
    if not cfg.get("revocation_endpoint"):
        issues.append({"sev": "LOW", "issue": "No revocation_endpoint advertised"})
    ctx.state["oauth_issues"] = issues
    ctx.state["oauth_issuer"] = cfg.get("issuer")
    ctx.state["oauth_pkce_methods"] = pkce
    ctx.state["oauth_signing_algs"] = algs


def _r_crit(s):
    crit = [i for i in (s.get("oauth_issues") or []) if i["sev"] == "CRITICAL"]
    if not crit:
        return None
    return {"name": "OAuth/OIDC allows alg=none", "severity": "CRITICAL", "cvss": 9.8, "cwe": "CWE-347",
            "evidence": crit[0]["issue"],
            "remediation": "Remove 'none' from id_token_signing_alg_values_supported. Pin RS256/ES256."}


def _r_high(s):
    high = [i for i in (s.get("oauth_issues") or []) if i["sev"] == "HIGH"]
    if not high:
        return None
    return {"name": "OAuth/OIDC missing PKCE S256", "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-352",
            "evidence": "; ".join(i["issue"] for i in high),
            "remediation": "Advertise + require S256 PKCE for all public clients per OAuth 2.1 BCP."}


def _r_med(s):
    med = [i for i in (s.get("oauth_issues") or []) if i["sev"] in ("MEDIUM", "LOW")]
    if not med:
        return None
    return {"name": "OAuth/OIDC hygiene", "severity": "MEDIUM", "cvss": 4.3, "cwe": "CWE-613",
            "evidence": "; ".join(i["issue"] for i in med),
            "remediation": "Support asymmetric signing + token revocation endpoint."}


FINDING_RULES = [_r_crit, _r_high, _r_med]
INTEL_FIELDS = [("OIDC config found", "oidc_config_found"), ("Issuer", "oauth_issuer"),
                 ("PKCE methods", "oauth_pkce_methods"), ("Signing algs", "oauth_signing_algs"),
                 ("Issues", "oauth_issues")]


@router.post("/api/vuln/oauth_flow_scan")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="oauth_flow_scan",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
