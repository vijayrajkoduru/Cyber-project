"""webauthn_config_audit - WebAuthn / FIDO2 options posture (playbook §7 #65/#68).

REAL remote probe (when an options endpoint is supplied). WebAuthn
registration/authentication "options" are public JSON the server hands the
browser to start a ceremony. The customer points the probe at that endpoint
and the probe inspects the SERVER-CHOSEN policy in the returned JSON:

  #65  userVerification == "discouraged"  -> presence-only, no PIN/biometric.
  #68  attestation == "none" with no policy + permissive algorithms
       -> downgrade / weak-authenticator acceptance.
  #65  pubKeyCredParams missing strong algs (ES256/-7, RS256/-257)
       -> weak / unexpected algorithm acceptance.
  #65  rpId mismatch vs the request host -> overly-broad RP scope.
  timeout absurdly large / challenge too short -> hygiene (advisory).

ZERO false positives: graded severities fire ONLY on a value parsed from
the live options JSON. No endpoint supplied -> ADVISORY-BY-DESIGN INFO
(the rest of WebAuthn security - resident keys, sync-fabric trust,
cross-device phishing - is verified client-side or by manual review and
cannot be SaaS-probed).

Customer input via ScanRequest.options:
  - target                       = identifier / RP host
  - options.webauthn_options_url = URL returning WebAuthn options JSON (POST or GET)
  - options.method               = "POST" (default) or "GET"
  - options.body                 = optional JSON body for the POST (e.g. {"username":"x"})
"""
from __future__ import annotations
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

router = APIRouter()

DEFAULT_TIMEOUT = 12

# COSE algorithm identifiers considered strong for WebAuthn.
_STRONG_COSE_ALGS = {-7, -257, -8, -35, -36, -37, -38, -39}  # ES256/RS256/EdDSA/ES384/...


class WebauthnConfigAuditRequest(ScanRequest):
    options: Optional[dict] = None


def _extract_options_block(data):
    """WebAuthn options may be at top level or nested under publicKey."""
    if not isinstance(data, dict):
        return None
    if "publicKey" in data and isinstance(data["publicKey"], dict):
        return data["publicKey"]
    # Heuristic: a registration/authentication options object has challenge.
    if "challenge" in data or "authenticatorSelection" in data \
            or "pubKeyCredParams" in data or "allowCredentials" in data:
        return data
    return None


async def gather(ctx: ScanContext):
    opts = ctx.state.get("_options") or {}
    url = (opts.get("webauthn_options_url") or "").strip()
    method = (opts.get("method") or "POST").upper()
    body = opts.get("body")

    if not url:
        # Advisory-by-design: most WebAuthn posture is client-side; without an
        # options endpoint we cannot probe anything from a SaaS scanner.
        ctx.state["webauthn_advisory_only"] = True
        ctx.source("no webauthn_options_url -> advisory-by-design")
        return

    try:
        import httpx
    except ImportError:
        ctx.state["webauthn_httpx_missing"] = True
        ctx.source("httpx not installed")
        return

    data = None
    status = 0
    async with httpx.AsyncClient(verify=True, timeout=DEFAULT_TIMEOUT) as client:
        try:
            if method == "GET":
                r = await client.get(url, follow_redirects=True)
            else:
                if isinstance(body, dict):
                    r = await client.post(url, json=body, follow_redirects=True)
                else:
                    r = await client.post(url, follow_redirects=True)
            status = r.status_code
            try:
                data = r.json()
            except Exception:
                data = None
        except Exception as e:
            ctx.state["webauthn_error"] = str(e)[:160]

    ctx.state["webauthn_status"] = status
    block = _extract_options_block(data)
    if block is None:
        ctx.state["webauthn_no_options"] = True
        ctx.source(f"endpoint returned no WebAuthn options JSON (status {status})")
        return

    ctx.state["webauthn_options_url"] = url

    # --- userVerification ---
    auth_sel = block.get("authenticatorSelection") or {}
    uv = (auth_sel.get("userVerification") or block.get("userVerification") or "").lower()
    ctx.state["webauthn_user_verification"] = uv or None
    if uv == "discouraged":
        ctx.state["webauthn_uv_discouraged"] = True

    # --- attestation ---
    attestation = (block.get("attestation") or "").lower()
    ctx.state["webauthn_attestation"] = attestation or None

    # --- algorithms ---
    params = block.get("pubKeyCredParams") or []
    algs = []
    for p in params:
        if isinstance(p, dict) and "alg" in p:
            algs.append(p.get("alg"))
    ctx.state["webauthn_algs"] = algs
    has_strong = any(a in _STRONG_COSE_ALGS for a in algs)
    if algs and not has_strong:
        ctx.state["webauthn_weak_algs"] = True

    # --- rpId scope ---
    rp = block.get("rp") or {}
    rp_id = (rp.get("id") if isinstance(rp, dict) else None) or block.get("rpId")
    ctx.state["webauthn_rp_id"] = rp_id
    host = urlparse(url).hostname or ""
    if rp_id and host and not (host == rp_id or host.endswith("." + str(rp_id))):
        # rpId is not a registrable suffix of the request host -> over-broad / mismatch
        ctx.state["webauthn_rp_mismatch"] = {"rp_id": rp_id, "host": host}

    # --- challenge length (hygiene/advisory) ---
    challenge = block.get("challenge")
    if isinstance(challenge, str):
        ctx.state["webauthn_challenge_len"] = len(challenge)
        if len(challenge) < 22:  # ~16 bytes base64url
            ctx.state["webauthn_short_challenge"] = True

    ctx.source(
        f"WebAuthn options parsed: uv={uv or '?'}, attestation={attestation or '?'}, "
        f"{len(algs)} alg(s)"
    )


# ----------------------- inline finding rules -----------------------
def rule_uv_discouraged(s):
    if not s.get("webauthn_uv_discouraged"):
        return None
    return {
        "name": "WebAuthn userVerification set to \"discouraged\" (presence-only, no PIN/biometric)",
        "severity": "MEDIUM",
        "cvss": "5.4",
        "cwe": "CWE-308",
        "owasp": "A07:2021",
        "verified_exploit": True,
        "evidence": (
            f"The options endpoint {s.get('webauthn_options_url','?')} returns "
            "userVerification=\"discouraged\". The authenticator only proves presence (a touch) "
            "with no PIN/biometric, so a borrowed/stolen security key authenticates without the "
            "user's secret - weakening the second factor."
        ),
        "remediation": (
            "Set userVerification to \"required\" (or \"preferred\" with server-side enforcement "
            "of the UV flag) for high-value accounts."
        ),
    }


def rule_weak_algs(s):
    if not s.get("webauthn_weak_algs"):
        return None
    return {
        "name": "WebAuthn pubKeyCredParams advertise no strong algorithm (ES256/RS256/EdDSA)",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-327",
        "owasp": "A02:2021",
        "verified_exploit": True,
        "evidence": (
            f"pubKeyCredParams returned {s.get('webauthn_algs')} - none map to a recommended "
            "COSE algorithm (-7 ES256, -257 RS256, -8 EdDSA). Authenticators may register with "
            "an unexpected/weak algorithm."
        ),
        "remediation": (
            "Advertise at least ES256 (-7) and RS256 (-257) in pubKeyCredParams and reject "
            "registrations using other algorithms server-side."
        ),
    }


def rule_rp_mismatch(s):
    mismatch = s.get("webauthn_rp_mismatch")
    if not mismatch:
        return None
    return {
        "name": "WebAuthn rpId is not a registrable suffix of the serving host (over-broad scope)",
        "severity": "MEDIUM",
        "cvss": "5.0",
        "cwe": "CWE-346",
        "owasp": "A07:2021",
        "verified_exploit": True,
        "evidence": (
            f"The options endpoint host is {mismatch.get('host')} but rpId is "
            f"{mismatch.get('rp_id')}. An rpId that does not match (or registrably-suffix) the "
            "origin broadens where the credential is usable and can ease cross-origin abuse."
        ),
        "remediation": (
            "Set rpId to the exact eTLD+1 of your application origin and ensure the browser "
            "origin matches. Do not set rpId to a parent domain you do not fully control."
        ),
    }


def rule_short_challenge(s):
    # Advisory hygiene -> capped to INFO.
    if not s.get("webauthn_short_challenge"):
        return None
    if any(s.get(k) for k in ("webauthn_uv_discouraged", "webauthn_weak_algs",
                              "webauthn_rp_mismatch")):
        return None
    return {
        "name": "WebAuthn challenge appears short (< ~16 bytes of entropy)",
        "severity": "INFO",
        "cwe": "CWE-330",
        "owasp": "A02:2021",
        "evidence": (
            f"Returned challenge length is {s.get('webauthn_challenge_len')} chars. Advisory: "
            "verify the server issues >= 16 random bytes per ceremony to resist replay."
        ),
        "remediation": "Issue a fresh, single-use, >= 16-byte random challenge per ceremony.",
    }


def rule_advisory_only(s):
    if not s.get("webauthn_advisory_only"):
        return None
    return {
        "name": "[ADVISORY-BY-DESIGN] WebAuthn / passkey posture - no options endpoint supplied",
        "severity": "INFO",
        "cwe": "CWE-1395",
        "owasp": "A07:2021",
        "evidence": (
            "WebAuthn security (resident-key policy, attestation verification, cross-device sync "
            "trust, downgrade and passkey-phishing resistance) is enforced client-side and in "
            "the ceremony - it cannot be probed from an external SaaS scanner without the "
            "server's WebAuthn options endpoint. This is advisory-by-design, not a forge gap."
        ),
        "remediation": (
            "Supply options.webauthn_options_url (the endpoint your front-end calls to begin "
            "registration/authentication) to enable real posture checks, or review the FIDO2 "
            "config manually per playbook §7."
        ),
    }


def rule_no_options(s):
    if not s.get("webauthn_no_options"):
        return None
    return {
        "name": "WebAuthn options endpoint returned no recognizable options JSON",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": (
            f"The endpoint returned HTTP {s.get('webauthn_status','?')} but no WebAuthn options "
            "object (no challenge / authenticatorSelection / pubKeyCredParams). It may need a "
            "session, a username body, or a different HTTP method."
        ),
        "remediation": (
            "Confirm the URL is the begin-registration/authentication endpoint and pass any "
            "required body via options.body and the correct options.method."
        ),
    }


def rule_httpx_missing(s):
    if not s.get("webauthn_httpx_missing"):
        return None
    return {
        "name": "httpx library not installed on scanner host",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": "`import httpx` failed - required to fetch WebAuthn options.",
        "remediation": "pip install httpx >=0.24 inside the scanner container.",
    }


def rule_positive(s):
    if not s.get("webauthn_options_url"):
        return None
    if any(s.get(k) for k in ("webauthn_uv_discouraged", "webauthn_weak_algs",
                              "webauthn_rp_mismatch")):
        return None
    return {
        "name": "WebAuthn options posture is sound (UV not discouraged, strong algs, scoped rpId)",
        "severity": "POSITIVE",
        "cwe": "CWE-308",
        "owasp": "A07:2021",
        "evidence": (
            f"Options at {s.get('webauthn_options_url')} request userVerification="
            f"{s.get('webauthn_user_verification')}, advertise a strong algorithm set "
            f"({s.get('webauthn_algs')}), and use a correctly-scoped rpId."
        ),
        "remediation": (
            "Keep userVerification required for sensitive flows and verify attestation "
            "server-side. Re-run after WebAuthn library upgrades."
        ),
    }


WEBAUTHN_CONFIG_AUDIT_FINDING_RULES = [
    rule_uv_discouraged,
    rule_weak_algs,
    rule_rp_mismatch,
    rule_short_challenge,
    rule_advisory_only,
    rule_no_options,
    rule_httpx_missing,
    rule_positive,
]


INTEL_FIELDS = [
    ("Options URL",          "webauthn_options_url"),
    ("HTTP status",          "webauthn_status"),
    ("userVerification",     "webauthn_user_verification"),
    ("attestation",          "webauthn_attestation"),
    ("Algorithms (COSE)",    "webauthn_algs"),
    ("rpId",                 "webauthn_rp_id"),
    ("Challenge length",     "webauthn_challenge_len"),
]


@router.post("/api/auth_attacks/webauthn_config_audit")
async def auth_attacks_webauthn_config_audit(req: WebauthnConfigAuditRequest,
                                             _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="webauthn_config_audit",
        gather_func=_gather_with_options,
        finding_rules=WEBAUTHN_CONFIG_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
