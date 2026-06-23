"""adfs_extract_audit - ADFS federation surface audit
(playbook §2 #20 ADFS Golden Ticket + #26 ADFS proxy attack surface +
§8 modern CVE/TTPs).

Performs four UNAUTHENTICATED checks against a customer-supplied ADFS
host:

  (a) GET /adfs/services/trust/mex
        — Federation Metadata Exchange. Confirms ADFS is running and
        leaks service-trust binding URLs (UsernameMixed, WindowsMixed,
        IssuedTokenMixed). Reveals ADFS version via SOAP namespace.

  (b) GET /federationmetadata/2007-06/federationmetadata.xml
        — SAML federation metadata. Discloses token-signing certificate
        (subject + thumbprint), issuer URI, entity ID. Used by
        AADInternals Get-AADIntADFSPolicyStoreCertificate.

  (c) Version probe + CVE-2017-11774
        ADFS versions prior to ADFS 4 (Windows Server 2016) lack
        anti-relay protection in the WS-Trust endpoints. Version is
        leaked in the build number inside the /adfs/ls/idpinitiatedsignon
        page (deprecated in 2019 but often still enabled) AND inside the
        mex XML. CVE-2017-11774 is an Outlook Forms RCE chain triggered
        via ADFS proxy auth bypass — we check whether the bypass surface
        exists (POST /adfs/ls/wia returning 200 without auth).

  (d) AADInternals-style metadata enum
        Pull ADFS configuration policy via /adfs/services/policystoreswstrust/
        and check for misconfigured cross-realm SAML claims.

Customer input via ScanRequest.options:
  - options.adfs_server_url = "https://sts.contoso.com" (required)

verify=False because customer ADFS often uses internal-CA certs.

CWE-295 Improper Certificate Validation
CWE-287 Improper Authentication
CWE-668 Exposure of Resource to Wrong Sphere
MITRE T1606.002 Forge Web Credentials: SAML Tokens (Golden SAML)
MITRE T1190 Exploit Public-Facing Application
"""
from __future__ import annotations
import asyncio
import re
from typing import Optional
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.adfs_extract_audit_findings import (
    ADFS_EXTRACT_AUDIT_FINDING_RULES,
)

router = APIRouter()

MEX_PATH = "/adfs/services/trust/mex"
SAML_METADATA_PATH = "/federationmetadata/2007-06/federationmetadata.xml"
IDPINIT_PATH = "/adfs/ls/idpinitiatedsignon.aspx"
WIA_PATH = "/adfs/ls/wia"
POLICY_STORE_PATH = "/adfs/services/policystoreswstrust/policyStore"

# ADFS version markers (build-number prefix -> human label)
ADFS_VERSION_MAP = [
    (re.compile(r"6\.[3-9]\."), "ADFS 6.x (Win Srv 2025)"),
    (re.compile(r"5\."),          "ADFS 5 (Win Srv 2022)"),
    (re.compile(r"4\."),          "ADFS 4 (Win Srv 2019)"),
    (re.compile(r"3\."),          "ADFS 3 (Win Srv 2016)"),
    (re.compile(r"2\.1"),         "ADFS 2.1 (Win Srv 2012)"),
    (re.compile(r"2\.0"),         "ADFS 2.0 (Win Srv 2008 R2) — EOL"),
]

_RE_BUILD = re.compile(r"build[=: ]?([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)
_RE_PRODUCT = re.compile(r"Microsoft\s+Identity\s+Server", re.I)
_RE_TS_CERT = re.compile(r"<X509Certificate>([^<]+)</X509Certificate>", re.I)
_RE_ISSUER = re.compile(r'entityID="([^"]+)"', re.I)
_RE_SOAP_ACTION = re.compile(r"<wsa:Action[^>]*>([^<]+)</wsa:Action>", re.I)
_RE_SAML_ENDPOINT = re.compile(r"Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:[^\"]+\"\s+Location=\"([^\"]+)\"", re.I)


class AdfsExtractRequest(ScanRequest):
    options: Optional[dict] = None


def _normalize_adfs_url(raw: str) -> str:
    u = (raw or "").strip().rstrip("/")
    if not u:
        return ""
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    return u


def _classify_version(text: str) -> tuple[Optional[str], Optional[str]]:
    """Return (build_string, friendly_label)."""
    m = _RE_BUILD.search(text or "")
    if not m:
        return None, None
    build = m.group(1)
    for pat, label in ADFS_VERSION_MAP:
        if pat.match(build):
            return build, label
    return build, f"ADFS build {build}"


async def _http_get(client, url: str, ua: str) -> tuple[int, str, dict]:
    try:
        r = await client.get(url, headers={"User-Agent": ua,
                                            "Accept": "application/xml,*/*"})
    except Exception as e:
        return 0, "", {"transport_error": f"{type(e).__name__}: {str(e)[:80]}"}
    body = r.text or ""
    return r.status_code, body, {"len": len(body),
                                    "ct": r.headers.get("content-type", ""),
                                    "server_hdr": r.headers.get("server", "")}


async def _http_post(client, url: str, ua: str, body: str = "") -> tuple[int, str]:
    try:
        r = await client.post(url, headers={"User-Agent": ua,
                                              "Content-Type": "application/soap+xml"},
                                content=body or "")
    except Exception:
        return 0, ""
    return r.status_code, (r.text or "")[:1000]


async def _run(req: AdfsExtractRequest, ctx: ScanContext):
    try:
        import httpx
    except ImportError:
        ctx.state["adfs_audit_error"] = "httpx not installed"
        ctx.source("httpx missing")
        return

    opts = req.options or {}
    adfs_url = _normalize_adfs_url(opts.get("adfs_server_url") or req.target)
    if not adfs_url:
        ctx.state["adfs_audit_no_url"] = True
        ctx.source("missing options.adfs_server_url")
        return

    ctx.state["adfs_audit_target_url"] = adfs_url
    ua = "VulnusLab/HybridIdentityAudit ADFSExtract/1.0"
    cve_signals: list[str] = []

    # Customer ADFS often has internal-CA certs; verify=False per spec.
    async with httpx.AsyncClient(timeout=15.0, verify=False,
                                  follow_redirects=True) as client:
        # (a) Federation Metadata Exchange
        mex_url = adfs_url + MEX_PATH
        mex_status, mex_body, mex_meta = await _http_get(client, mex_url, ua)
        ctx.state["adfs_audit_mex_status"] = mex_status
        ctx.state["adfs_audit_mex_size"] = mex_meta.get("len", 0)
        ctx.state["adfs_audit_mex_server"] = mex_meta.get("server_hdr") or ""

        mex_reachable = (mex_status == 200 and "wsdl" in (mex_body or "").lower())
        ctx.state["adfs_audit_mex_reachable"] = mex_reachable

        bindings: list[str] = []
        if mex_reachable:
            # Extract WS-Trust binding addresses
            for m in re.finditer(r'<wsa:Address>([^<]+)</wsa:Address>', mex_body, re.I):
                addr = m.group(1).strip()
                if "/adfs/services/trust/" in addr.lower():
                    bindings.append(addr)
        ctx.state["adfs_audit_ws_trust_bindings"] = sorted(set(bindings))[:20]

        # (b) SAML federation metadata
        saml_url = adfs_url + SAML_METADATA_PATH
        saml_status, saml_body, _ = await _http_get(client, saml_url, ua)
        ctx.state["adfs_audit_saml_status"] = saml_status
        saml_ok = (saml_status == 200 and "EntityDescriptor" in (saml_body or ""))
        ctx.state["adfs_audit_saml_metadata_reachable"] = saml_ok

        ts_cert_b64 = None
        issuer = None
        saml_endpoints: list[str] = []
        if saml_ok:
            m = _RE_TS_CERT.search(saml_body)
            ts_cert_b64 = (m.group(1).strip()[:80] + "...") if m else None
            m = _RE_ISSUER.search(saml_body)
            issuer = m.group(1) if m else None
            for em in _RE_SAML_ENDPOINT.finditer(saml_body):
                saml_endpoints.append(em.group(1))
        ctx.state["adfs_audit_ts_cert_preview"] = ts_cert_b64
        ctx.state["adfs_audit_issuer"] = issuer
        ctx.state["adfs_audit_saml_endpoints"] = saml_endpoints[:10]

        # (c) Version probe — try idpinitiatedsignon (legacy)
        idp_url = adfs_url + IDPINIT_PATH
        idp_status, idp_body, idp_meta = await _http_get(client, idp_url, ua)
        ctx.state["adfs_audit_idpinit_status"] = idp_status
        idpinit_enabled = (idp_status == 200 and "Sign in to" in (idp_body or ""))
        ctx.state["adfs_audit_idpinit_enabled"] = idpinit_enabled

        # Combine all bodies for build/version search
        combined = (mex_body or "") + "\n" + (saml_body or "") + "\n" + (idp_body or "")
        build_str, friendly = _classify_version(combined)
        ctx.state["adfs_audit_build"] = build_str
        ctx.state["adfs_audit_version_label"] = friendly

        is_legacy = friendly is not None and (
            "ADFS 2.0" in friendly or
            "ADFS 2.1" in friendly or
            "ADFS 3" in friendly)
        ctx.state["adfs_audit_is_legacy"] = is_legacy

        # CVE-2017-11774 surface: WIA endpoint reachable without auth?
        wia_url = adfs_url + WIA_PATH
        wia_status, wia_body = await _http_post(client, wia_url, ua, "")
        ctx.state["adfs_audit_wia_status"] = wia_status
        # 401 = expected (challenge). 200/302 with no auth = bypass surface.
        wia_bypass_surface = wia_status in (200, 302)
        ctx.state["adfs_audit_wia_bypass_surface"] = wia_bypass_surface
        if wia_bypass_surface:
            # ZERO-FP: only call it a CVE-2017-11774 signal when the version is
            # KNOWN-legacy (the CVE precondition). On unknown/non-legacy
            # versions record it as a surface observation, not a CVE claim.
            if is_legacy:
                cve_signals.append(
                    "CVE-2017-11774 precondition met — WIA endpoint reachable "
                    "without auth challenge on legacy ADFS")
            else:
                cve_signals.append(
                    "WIA endpoint reachable without auth challenge "
                    "(surface only — ADFS version not known-vulnerable, "
                    "CVE-2017-11774 not asserted)")

        # (d) AADInternals-style policy store probe
        ps_url = adfs_url + POLICY_STORE_PATH
        ps_status, ps_body, _ = await _http_get(client, ps_url, ua)
        # The policy store endpoint should require auth -> 401 expected
        ctx.state["adfs_audit_policystore_status"] = ps_status
        ctx.state["adfs_audit_policystore_anonymous_reachable"] = (ps_status == 200)
        if ps_status == 200:
            cve_signals.append("Policy store reachable anonymously — AADInternals "
                                "Get-AADIntADFSPolicyStoreToken precondition met")

        # Anonymous federation metadata IS expected. Legacy idpinitiated being
        # enabled is a phishing-amplification finding.
        if idpinit_enabled and is_legacy:
            cve_signals.append("idpinitiatedsignon.aspx ENABLED on legacy ADFS — "
                                "phishing landing page surface")

        ctx.state["adfs_audit_cve_signals"] = cve_signals
        ctx.state["adfs_audit_cve_signal_count"] = len(cve_signals)

    ctx.source(f"ADFS audit: mex={mex_reachable} saml={saml_ok} "
               f"version={friendly or 'unknown'} legacy={is_legacy} "
               f"signals={len(cve_signals)}")


INTEL_FIELDS = [
    ("ADFS target URL",         "adfs_audit_target_url"),
    ("ADFS build",              "adfs_audit_build"),
    ("ADFS version",            "adfs_audit_version_label"),
    ("Is legacy ADFS?",         "adfs_audit_is_legacy"),
    ("MEX reachable",           "adfs_audit_mex_reachable"),
    ("MEX server header",       "adfs_audit_mex_server"),
    ("WS-Trust bindings",       "adfs_audit_ws_trust_bindings"),
    ("SAML metadata reachable", "adfs_audit_saml_metadata_reachable"),
    ("Federation issuer URI",   "adfs_audit_issuer"),
    ("Token-signing cert (b64 preview)", "adfs_audit_ts_cert_preview"),
    ("SAML SSO endpoints",      "adfs_audit_saml_endpoints"),
    ("idpinitiatedsignon enabled", "adfs_audit_idpinit_enabled"),
    ("WIA endpoint status",     "adfs_audit_wia_status"),
    ("WIA bypass surface",      "adfs_audit_wia_bypass_surface"),
    ("Policy store status",     "adfs_audit_policystore_status"),
    ("CVE / TTP signals",       "adfs_audit_cve_signals"),
]


@router.post("/api/hybrid_identity/adfs_extract_audit")
async def hybrid_identity_adfs_extract_audit(req: AdfsExtractRequest,
                                              _=Depends(verify_scan_quota)):
    async def _gather(ctx: ScanContext):
        await _run(req, ctx)
    return await run_scanner(
        host=req.target, tool="adfs_extract_audit",
        gather_func=_gather,
        finding_rules=ADFS_EXTRACT_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
