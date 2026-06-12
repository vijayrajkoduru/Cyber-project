"""jwks_exposure_audit - JWKS / signing-key hygiene audit (playbook §5 #48/#53).

REAL remote probe. Fetches the customer's JSON Web Key Set (JWKS) - either
directly from options.jwks_uri or auto-discovered from the OIDC discovery
document at the target - and inspects every published key for weaknesses
that enable token forgery:

  - Symmetric ("oct") keys published in a PUBLIC JWKS  -> anyone can re-sign
    HS256 tokens with the leaked shared secret (key-confusion enabler, #53).
  - RSA keys < 2048 bits (or EC < 256)                 -> brute-forceable.
  - Keys missing a "kid"                               -> kid-confusion / rotation hard.
  - "alg":"none" advertised in the discovery doc       -> alg=none forgery (#45).

ZERO false positives: a graded severity is emitted ONLY when a weak key was
actually retrieved and parsed from the live JWKS. Unreachable JWKS, missing
input, or an all-strong key set -> INFO / POSITIVE only.

Customer input via ScanRequest.options:
  - target              = base URL of the IdP (used for OIDC auto-discovery)
  - options.jwks_uri    = explicit JWKS URL (skips discovery) - optional
  - options.issuer      = OIDC issuer base (for discovery) - optional, default target

Privacy: only key metadata (kty, alg, kid, bit-length) is reported. The
modulus / key material is never echoed.
"""
from __future__ import annotations
import base64
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

router = APIRouter()

DEFAULT_TIMEOUT = 12


class JwksExposureAuditRequest(ScanRequest):
    options: Optional[dict] = None


def _normalize_base(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    if url and not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _b64url_len_bits(b64: str) -> int:
    """Return the bit length of a base64url-encoded big-endian integer."""
    try:
        s = b64.split("=")[0]
        pad = "=" * (-len(s) % 4)
        raw = base64.urlsafe_b64decode(s + pad)
        # Strip a single leading zero byte often present on positive ints.
        raw = raw.lstrip(b"\x00") or b"\x00"
        return len(raw) * 8
    except Exception:
        return 0


async def _fetch_json(client, url: str):
    try:
        r = await client.get(url, follow_redirects=True)
        if r.status_code != 200:
            return None, r.status_code
        return r.json(), r.status_code
    except Exception:
        return None, 0


async def gather(ctx: ScanContext):
    opts = ctx.state.get("_options") or {}
    base = _normalize_base(opts.get("issuer") or ctx.host or "")
    jwks_uri = (opts.get("jwks_uri") or "").strip()

    if not base and not jwks_uri:
        ctx.state["jwks_input_missing"] = True
        ctx.source("missing target / jwks_uri")
        return

    try:
        import httpx
    except ImportError:
        ctx.state["jwks_httpx_missing"] = True
        ctx.source("httpx not installed")
        return

    weak_keys = []
    oct_keys = []
    missing_kid = []
    key_summaries = []
    none_alg_advertised = False

    async with httpx.AsyncClient(verify=True, timeout=DEFAULT_TIMEOUT) as client:
        # 1. Resolve JWKS URI (explicit or via OIDC discovery)
        if not jwks_uri and base:
            disc_url = base.rstrip("/") + "/.well-known/openid-configuration"
            disc, disc_status = await _fetch_json(client, disc_url)
            ctx.state["jwks_discovery_status"] = disc_status
            if isinstance(disc, dict):
                jwks_uri = (disc.get("jwks_uri") or "").strip()
                ctx.state["jwks_discovery_ok"] = True
                # Note alg=none being advertised as supported
                algs = disc.get("id_token_signing_alg_values_supported") or []
                if isinstance(algs, list) and any(
                    str(a).lower() == "none" for a in algs
                ):
                    none_alg_advertised = True

        if not jwks_uri:
            ctx.state["jwks_not_found"] = True
            ctx.source("no jwks_uri discoverable")
            return

        ctx.state["jwks_uri"] = jwks_uri
        ctx.state["jwks_none_alg_advertised"] = none_alg_advertised

        # 2. Fetch the key set
        jwks, jwks_status = await _fetch_json(client, jwks_uri)
        ctx.state["jwks_fetch_status"] = jwks_status
        if not isinstance(jwks, dict) or "keys" not in jwks:
            ctx.state["jwks_unreachable"] = True
            ctx.source(f"JWKS fetch failed (status {jwks_status})")
            return

        keys = jwks.get("keys") or []
        ctx.state["jwks_key_count"] = len(keys)

        for k in keys:
            if not isinstance(k, dict):
                continue
            kty = (k.get("kty") or "").upper()
            kid = k.get("kid")
            alg = k.get("alg")
            summary = {"kty": kty, "kid": kid, "alg": alg}

            if kid in (None, ""):
                missing_kid.append(summary)

            if kty == "OCT":
                # Symmetric key published in a public JWKS - serious.
                oct_keys.append(summary)
            elif kty == "RSA":
                bits = _b64url_len_bits(k.get("n") or "")
                summary["bits"] = bits
                if 0 < bits < 2048:
                    weak_keys.append(summary)
            elif kty == "EC":
                crv = k.get("crv") or ""
                summary["crv"] = crv
                # P-192 / weak curves
                if crv in ("P-192", "secp192r1"):
                    weak_keys.append(summary)
            key_summaries.append(summary)

    ctx.state["jwks_keys"] = key_summaries
    ctx.state["jwks_oct_keys"] = oct_keys
    ctx.state["jwks_weak_keys"] = weak_keys
    ctx.state["jwks_missing_kid"] = missing_kid
    ctx.source(
        f"JWKS inspected: {len(key_summaries)} key(s), "
        f"{len(oct_keys)} symmetric, {len(weak_keys)} weak"
    )


# ----------------------- inline finding rules -----------------------
def rule_oct_in_public_jwks(s):
    oct_keys = s.get("jwks_oct_keys") or []
    if not oct_keys:
        return None
    return {
        "name": f"Symmetric (oct) signing key published in PUBLIC JWKS: {len(oct_keys)} key(s)",
        "severity": "CRITICAL",
        "cvss": "9.1",
        "cwe": "CWE-321",
        "owasp": "A02:2021",
        "verified_exploit": True,
        "evidence": (
            f"The JWKS at {s.get('jwks_uri','?')} publishes {len(oct_keys)} HMAC/symmetric "
            f"(kty=oct) key(s). A symmetric key in a PUBLIC key set means the shared HMAC "
            f"secret is downloadable by anyone - they can forge valid HS256 tokens for any "
            f"user. Key ids: {[k.get('kid') for k in oct_keys]}."
        ),
        "remediation": (
            "1. Remove every oct key from the public JWKS immediately - symmetric keys must "
            "NEVER be exposed. 2. Rotate the leaked secret. 3. Switch the IdP to asymmetric "
            "signing (RS256/ES256) so the public JWKS only ever exposes verification (public) "
            "keys. 4. Re-run after rotation."
        ),
    }


def rule_weak_asymmetric_key(s):
    weak = s.get("jwks_weak_keys") or []
    if not weak:
        return None
    return {
        "name": f"Weak signing key in JWKS: {len(weak)} key(s) below 2048-bit RSA / weak curve",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-326",
        "owasp": "A02:2021",
        "verified_exploit": True,
        "evidence": (
            f"The JWKS at {s.get('jwks_uri','?')} contains key(s) below modern strength: "
            f"{weak}. RSA below 2048 bits / EC below P-256 is factorable / brute-forceable, "
            "letting an attacker recover the private key and forge tokens."
        ),
        "remediation": (
            "Re-key the IdP with RSA >= 2048 (3072 preferred) or EC P-256/P-384, publish the "
            "new public key in the JWKS, retire the weak kid, then re-run."
        ),
    }


def rule_none_alg_advertised(s):
    if not s.get("jwks_none_alg_advertised"):
        return None
    return {
        "name": "OIDC discovery advertises alg=none as a supported id_token signing algorithm",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-347",
        "owasp": "A02:2021",
        "verified_exploit": True,
        "evidence": (
            f"id_token_signing_alg_values_supported at {s.get('jwks_uri','the discovery doc')} "
            "includes \"none\". Any relying party that trusts this list may accept unsigned "
            "id_tokens, enabling trivial token forgery (alg=none, playbook #45)."
        ),
        "remediation": (
            "Remove \"none\" from id_token_signing_alg_values_supported in the IdP config. "
            "Only advertise RS256/ES256/PS256. Ensure RPs hard-code the expected alg."
        ),
    }


def rule_missing_kid(s):
    # Advisory-only hygiene note (capped to INFO by phrasing); never graded.
    missing = s.get("jwks_missing_kid") or []
    if not missing:
        return None
    if (s.get("jwks_oct_keys") or s.get("jwks_weak_keys")):
        # Don't add noise when there's a real graded finding.
        return None
    return {
        "name": f"JWKS keys missing 'kid' header: {len(missing)} key(s)",
        "severity": "INFO",
        "cwe": "CWE-320",
        "owasp": "A02:2021",
        "evidence": (
            f"{len(missing)} published key(s) lack a 'kid' identifier. Not exploitable on its "
            "own, but it complicates safe key rotation and is a precondition reviewers should "
            "note."
        ),
        "remediation": (
            "Add a unique, stable 'kid' to every JWK so relying parties can select the right "
            "key during rotation."
        ),
    }


def rule_input_missing(s):
    if not s.get("jwks_input_missing"):
        return None
    return {
        "name": "JWKS exposure audit skipped - no target or jwks_uri supplied",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": (
            "Probe needs either ScanRequest.target (for OIDC auto-discovery) or "
            "options.jwks_uri (the direct JWKS URL)."
        ),
        "remediation": "Re-run with the IdP base URL as target, or paste options.jwks_uri.",
    }


def rule_httpx_missing(s):
    if not s.get("jwks_httpx_missing"):
        return None
    return {
        "name": "httpx library not installed on scanner host",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": "`import httpx` failed - required to fetch the JWKS.",
        "remediation": "pip install httpx >=0.24 inside the scanner container.",
    }


def rule_unreachable(s):
    if not (s.get("jwks_unreachable") or s.get("jwks_not_found")):
        return None
    return {
        "name": "JWKS could not be retrieved from the target",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": (
            f"No usable JWKS was reachable (discovery status "
            f"{s.get('jwks_discovery_status','?')}, jwks status "
            f"{s.get('jwks_fetch_status','?')}). No keys could be inspected."
        ),
        "remediation": (
            "Confirm the IdP exposes /.well-known/openid-configuration with a reachable "
            "jwks_uri, or supply options.jwks_uri directly."
        ),
    }


def rule_positive(s):
    if s.get("jwks_input_missing") or s.get("jwks_httpx_missing"):
        return None
    if s.get("jwks_unreachable") or s.get("jwks_not_found"):
        return None
    if s.get("jwks_oct_keys") or s.get("jwks_weak_keys") or s.get("jwks_none_alg_advertised"):
        return None
    count = s.get("jwks_key_count")
    if not count:
        return None
    return {
        "name": f"JWKS is clean: {count} key(s), all asymmetric and >=2048-bit / strong curve",
        "severity": "POSITIVE",
        "cwe": "CWE-320",
        "owasp": "A02:2021",
        "evidence": (
            f"The key set at {s.get('jwks_uri','?')} published {count} key(s); none were "
            "symmetric, none were below modern strength, and alg=none was not advertised."
        ),
        "remediation": (
            "Maintain regular key rotation and keep the JWKS asymmetric-only. Re-run after "
            "each rotation."
        ),
    }


JWKS_EXPOSURE_AUDIT_FINDING_RULES = [
    rule_oct_in_public_jwks,
    rule_weak_asymmetric_key,
    rule_none_alg_advertised,
    rule_missing_kid,
    rule_input_missing,
    rule_httpx_missing,
    rule_unreachable,
    rule_positive,
]


INTEL_FIELDS = [
    ("JWKS URI",              "jwks_uri"),
    ("Discovery status",      "jwks_discovery_status"),
    ("JWKS fetch status",     "jwks_fetch_status"),
    ("Key count",             "jwks_key_count"),
    ("Keys (metadata)",       "jwks_keys"),
    ("Symmetric keys",        "jwks_oct_keys"),
    ("Weak keys",             "jwks_weak_keys"),
    ("Keys missing kid",      "jwks_missing_kid"),
    ("alg=none advertised",   "jwks_none_alg_advertised"),
]


@router.post("/api/auth_attacks/jwks_exposure_audit")
async def auth_attacks_jwks_exposure_audit(req: JwksExposureAuditRequest,
                                            _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="jwks_exposure_audit",
        gather_func=_gather_with_options,
        finding_rules=JWKS_EXPOSURE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
