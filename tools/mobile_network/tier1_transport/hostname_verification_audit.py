"""hostname_verification_audit - HostnameVerifier ALLOW_ALL overrides.

Catches HostnameVerifier with return true (or ALLOW_ALL_HOSTNAME_VERIFIER)
plus TrustManager.checkServerTrusted() empty override (TLS-bypass). Same
defect that broke many production apps. MSTG-NETWORK-3."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.hostname_verification_audit_findings import HOSTNAME_VERIFICATION_AUDIT_FINDING_RULES

router = APIRouter()
ALLOW_ALL_RE = re.compile(r'ALLOW_ALL_HOSTNAME_VERIFIER|SSLConnectionSocketFactory\.ALLOW_ALL|TrustAllHostnameVerifier')
EMPTY_VERIFIER_RE = re.compile(r'HostnameVerifier[^}]*verify\([^)]*\)\s*\{\s*return\s+true', re.DOTALL)
EMPTY_TRUST_RE = re.compile(r'checkServerTrusted\s*\([^)]*\)\s*(?:throws[^{]+)?\{\s*\}', re.DOTALL)
IOS_TRUST_DISABLE_RE = re.compile(
    r'serverTrustPolicyManager|disableEvaluation|allowInvalidCertificates\s*=\s*true|'
    r'kCFStreamSSLValidatesCertificateChain.*?kCFBooleanFalse'
)
# presence != usage: the override must actually be wired into a TLS path. We
# require a co-located TLS/socket-factory/HTTP-client marker; an isolated
# ALLOW_ALL constant or an unused verifier class is not a live bypass.
TLS_USE_RE = re.compile(
    r'setHostnameVerifier|setSSLSocketFactory|HttpsURLConnection|SSLContext|'
    r'OkHttpClient|sslSocketFactory|hostnameVerifier\s*\(|setDefaultHostnameVerifier|'
    r'URLSession|SecTrust|sessionWithConfiguration'
)
# test / mock / sample harness paths: a TLS-bypass there is not the shipping
# app's defect -> downgrade to INFO.
TEST_PATH_RE = re.compile(r'(?:^|/|\\)(?:test|androidTest|mock|sample|example|debug|fixture|stub)',
                          re.IGNORECASE)
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["hostname_verification_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["hostname_verification_audit_error"] = str(e); return
    allow_all_users, empty_verifiers = [], []
    empty_trust, ios_disable = [], []
    test_only_hits = []   # bypass markers seen only in test/mock harness paths
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".swift", ".m", ".h"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        is_test = bool(TEST_PATH_RE.search(str(p)))
        has_tls_path = bool(TLS_USE_RE.search(txt))

        hit_allow = bool(ALLOW_ALL_RE.search(txt))
        hit_verifier = bool(EMPTY_VERIFIER_RE.search(txt))
        hit_trust = bool(EMPTY_TRUST_RE.search(txt))
        hit_ios = bool(IOS_TRUST_DISABLE_RE.search(txt))

        if not (hit_allow or hit_verifier or hit_trust or hit_ios):
            continue

        # Route test/mock harness hits to an INFO bucket; they are not the
        # shipping app's TLS posture.
        if is_test:
            if len(test_only_hits) < 20:
                test_only_hits.append(p.name)
            continue

        # ALLOW_ALL_HOSTNAME_VERIFIER as a bare constant/import is only a real
        # bypass when it is actually plumbed into a TLS path. The structural
        # empty-override patterns are self-evidently live and don't need this.
        if hit_allow and not (hit_verifier or hit_trust) and not has_tls_path:
            if len(test_only_hits) < 20:
                test_only_hits.append(p.name)
            continue

        if hit_allow and len(allow_all_users) < 20:
            allow_all_users.append(p.name)
        if hit_verifier and len(empty_verifiers) < 20:
            empty_verifiers.append(p.name)
        if hit_trust and len(empty_trust) < 20:
            empty_trust.append(p.name)
        if hit_ios and len(ios_disable) < 20:
            ios_disable.append(p.name)
    findings_total = 0
    if allow_all_users or empty_verifiers or empty_trust or ios_disable:
        findings_total += 1
    ctx.state["allow_all_users"] = allow_all_users
    ctx.state["empty_verifiers"] = empty_verifiers
    ctx.state["empty_trust_managers"] = empty_trust
    ctx.state["ios_trust_disabled"] = ios_disable
    ctx.state["test_only_bypass_hits"] = test_only_hits
    ctx.state["files_scanned"] = files_scanned
    ctx.state["hostname_verification_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("ALLOW_ALL_HOSTNAME_VERIFIER users", "allow_all_users"),
                ("Empty HostnameVerifier overrides", "empty_verifiers"),
                ("Empty TrustManager.checkServerTrusted", "empty_trust_managers"),
                ("iOS server trust disabled", "ios_trust_disabled"),
                ("Test/mock-only bypass markers (info)", "test_only_bypass_hits")]


@router.post("/api/mobile_network/hostname_verification_audit")
async def mobile_network_hostname_verification_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="hostname_verification_audit",
        gather_func=gather, finding_rules=HOSTNAME_VERIFICATION_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
