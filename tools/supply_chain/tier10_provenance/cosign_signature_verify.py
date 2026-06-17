"""cosign_signature_verify - Sigstore/cosign image signature verification (playbook §5 #60).

Upgrades a previously advisory-only technique into a REAL, read-only check that
runs when the customer supplies an OCI image reference. This is detection /
discovery only (VA): it never pushes, signs, attaches, or modifies anything in
any registry; it pulls signature metadata anonymously and (optionally) runs a
keyless trust verification against a customer-supplied identity policy.

Customer input precedence:
  1. CosignVerifyRequest.image_ref   e.g. "ghcr.io/org/app:1.2.3"
  2. CosignVerifyRequest.target      only if it looks like an OCI ref
                                     (contains '/' and is not an http(s) URL)

Optional trust policy (both required to fully verify):
  - certificate_identity      e.g. "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1"
  - certificate_oidc_issuer   e.g. "https://token.actions.githubusercontent.com"

What it does (SAFE):
  STEP 1  `cosign triangulate <image>`  — locates the signature artifact tag.
          A clean rc==0 with a non-empty resolved .sig ref => a signature MAY
          exist; corroborated in step 2 by `cosign verify`.
  STEP 2a `cosign verify <image>`        — (no identity) confirms whether ANY
          Sigstore signature is actually present + parseable. This is the
          authoritative presence signal (triangulate only computes a tag).
  STEP 2b `cosign verify <image> --certificate-identity <id>
          --certificate-oidc-issuer <iss>` — (only when BOTH supplied) full
          keyless trust verification against the expected identity/issuer.

ZERO-FALSE-POSITIVE policy:
  - An image is flagged UNSIGNED only when cosign DEFINITIVELY reports no
    signature (clean "no signatures found" / "no matching signatures"), never
    on auth/network/registry errors.
  - Ambiguous auth/network errors -> INFO ("could not determine").
  - Graded posture findings cap at MEDIUM. The unsigned posture finding is
    confidence SUSPECTED (verified_exploit False); the identity-mismatch finding
    is confidence CONFIRMED + verified_exploit True (cosign proved the mismatch).
"""
from __future__ import annotations
import asyncio
import shutil
from typing import Optional
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

router = APIRouter()
COSIGN_BIN = shutil.which("cosign") or "/usr/local/bin/cosign"
TIMEOUT = 60


class CosignVerifyRequest(ScanRequest):
    certificate_identity: Optional[str] = None
    certificate_oidc_issuer: Optional[str] = None


def _looks_like_image_ref(value: str) -> bool:
    """An OCI image ref contains a '/' (registry/repo) and is not an URL.
    Accepts forms like ghcr.io/org/app:tag, docker.io/library/nginx:1.27."""
    if not value:
        return False
    v = value.strip()
    if v.lower().startswith(("http://", "https://")):
        return False
    if " " in v:
        return False
    return "/" in v


def _tail(b: bytes, n: int = 400) -> str:
    """Decode + trim a stderr/stdout blob for safe display."""
    if not b:
        return ""
    txt = b.decode("utf-8", errors="ignore").strip()
    if len(txt) > n:
        txt = "..." + txt[-n:]
    return txt


# Definitive "no signature" markers cosign prints to stderr when an image has
# no associated Sigstore signature artifact. Matching ONE of these is the only
# way an image gets flagged unsigned (zero-FP gate).
_NO_SIG_MARKERS = (
    "no signatures found",
    "no matching signatures",
    "manifest unknown",                 # the .sig tag does not exist in the registry
    "no signatures associated",
)
# Auth / network / registry ambiguity -> never flag, emit INFO.
_AMBIGUOUS_MARKERS = (
    "unauthorized",
    "authentication required",
    "denied",
    "forbidden",
    "no such host",
    "connection refused",
    "timeout",
    "i/o timeout",
    "tls",
    "x509",
    "name resolution",
    "temporary failure",
    "could not",
    "rate limit",
    "too many requests",
)


async def _run(cmd: list, timeout: int = TIMEOUT):
    """Run a cosign subcommand. Returns (rc, stdout_bytes, stderr_bytes) or
    (None, b"", b"<reason>") on spawn/timeout failure."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
    except Exception as e:
        return None, b"", f"subprocess error: {str(e)[:120]}".encode()
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return None, b"", f"timeout after {timeout}s".encode()
    return proc.returncode, stdout or b"", stderr or b""


def _classify_err(text: str) -> str:
    """Return 'no_sig' | 'ambiguous' | 'other' for a cosign stderr blob."""
    low = (text or "").lower()
    if any(m in low for m in _NO_SIG_MARKERS):
        return "no_sig"
    if any(m in low for m in _AMBIGUOUS_MARKERS):
        return "ambiguous"
    return "other"


def _make_gather(req: CosignVerifyRequest):
    async def gather(ctx: ScanContext):
        # --- resolve image reference -------------------------------------
        image = (getattr(req, "image_ref", None) or "").strip()
        if not image:
            cand = (ctx.host or "").strip()
            if _looks_like_image_ref(cand):
                image = cand
        if not image:
            ctx.state["cosign_no_input"] = True
            ctx.source("image_ref required")
            return
        ctx.state["cosign_image"] = image

        # --- binary present? ---------------------------------------------
        if not (shutil.which("cosign") or COSIGN_BIN):
            ctx.state["cosign_binary_missing"] = True
            ctx.source("cosign missing")
            return
        bin_path = shutil.which("cosign") or COSIGN_BIN

        identity = (getattr(req, "certificate_identity", None) or "").strip()
        issuer = (getattr(req, "certificate_oidc_issuer", None) or "").strip()
        has_policy = bool(identity and issuer)
        ctx.state["cosign_identity_supplied"] = has_policy

        # --- STEP 1: triangulate (locate signature tag) ------------------
        rc, out, err = await _run([bin_path, "triangulate", image])
        tri_text = _tail(out) or _tail(err)
        if rc == 0 and out and out.strip():
            ctx.state["cosign_sig_ref"] = _tail(out, 200)
        ctx.source(f"cosign triangulate rc={rc if rc is not None else 'n/a'}")

        # --- STEP 2a: corroborate presence via verify (no identity) ------
        # cosign verify with no identity flags still parses + reports whether a
        # signature artifact actually exists. We read presence from this, NOT
        # from triangulate (which only computes a tag).
        rc2, out2, err2 = await _run([bin_path, "verify", image])
        v_err = _tail(err2)
        v_class = _classify_err(v_err)
        ctx.source(f"cosign verify rc={rc2 if rc2 is not None else 'n/a'}")

        if rc2 is None:
            # spawn/timeout — cannot determine
            ctx.state["cosign_error"] = v_err or "verify did not complete"
            return

        if v_class == "no_sig":
            # Definitive: registry has no signature artifact for this image.
            ctx.state["cosign_signature_present"] = False
        elif v_class == "ambiguous":
            # Auth/network/registry problem -> cannot determine. Never flag.
            ctx.state["cosign_error"] = v_err or "ambiguous registry/network error"
            return
        else:
            # rc==0 OR a non-presence error (e.g. cosign needs identity flags to
            # complete keyless verification but the signature DOES exist).
            # Newer cosign requires --certificate-identity for keyless verify and
            # exits non-zero with a policy-related message while still proving a
            # signature is present. Treat both as "present".
            ctx.state["cosign_signature_present"] = True

        # --- STEP 2b: full keyless trust verification --------------------
        if ctx.state.get("cosign_signature_present") and has_policy:
            rc3, out3, err3 = await _run([
                bin_path, "verify", image,
                "--certificate-identity", identity,
                "--certificate-oidc-issuer", issuer,
            ])
            ctx.source(f"cosign verify (identity) rc={rc3 if rc3 is not None else 'n/a'}")
            if rc3 is None:
                ctx.state["cosign_error"] = _tail(err3) or "identity verify did not complete"
            elif rc3 == 0:
                ctx.state["cosign_verified"] = True
            else:
                e3 = _tail(err3)
                if _classify_err(e3) == "ambiguous":
                    # network/auth flake during the identity check -> don't grade
                    ctx.state["cosign_error"] = e3 or "ambiguous error during identity verify"
                else:
                    # Signature exists but does NOT match the expected policy.
                    ctx.state["cosign_verified"] = False
                    ctx.state["cosign_verify_failed"] = True
                    ctx.state["cosign_verify_stderr"] = e3
    return gather


# ───────────────────────── finding rules (inline) ─────────────────────────

def _rule_no_input(s):
    if not s.get("cosign_no_input"):
        return None
    return {"name": "cosign_signature_verify: image reference required",
            "severity": "INFO",
            "evidence": "No OCI image reference was supplied. Provide "
                        "image_ref=registry/repo:tag (e.g. ghcr.io/org/app:1.2.3) "
                        "to verify its Sigstore signature.",
            "remediation": "Re-run with image_ref set to the container image you "
                           "want to check.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_binary_missing(s):
    if not s.get("cosign_binary_missing"):
        return None
    return {"name": "cosign_signature_verify: cosign binary unavailable",
            "severity": "INFO",
            "evidence": "The cosign binary was not found in the scanner "
                        "environment, so signature status could not be checked.",
            "remediation": "Install Sigstore cosign in the scanner image.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_error(s):
    err = s.get("cosign_error")
    if not err:
        return None
    img = s.get("cosign_image") or "the image"
    return {"name": "cosign_signature_verify: could not determine signature status",
            "severity": "INFO",
            "evidence": f"cosign could not conclusively determine the signature "
                        f"status of {img} (likely an authentication, registry, or "
                        f"network condition): {err}",
            "remediation": "Confirm the image reference is correct and the registry "
                           "is reachable anonymously, then re-run. Signature status "
                           "is reported as UNKNOWN, not as a finding.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_unsigned_image(s):
    # Only fire when cosign DEFINITIVELY reported no signature.
    if s.get("cosign_signature_present") is not False:
        return None
    if s.get("cosign_error"):
        return None
    img = s.get("cosign_image") or "the image"
    return {"name": "Container image has no Sigstore signature",
            "severity": "LOW", "cvss": "3.7",
            "confidence": "SUSPECTED",
            "cwe": "CWE-347", "owasp": "A08:2021",
            "verified_exploit": False,
            "evidence": f"cosign found no Sigstore signature artifact for {img}. "
                        "An unsigned image cannot be cryptographically attributed "
                        "to a trusted build pipeline, weakening supply-chain "
                        "provenance and admission-time integrity guarantees.",
            "remediation": "Sign images with cosign keyless signing (Fulcio/Rekor) "
                           "in CI, and enforce signature verification at admission "
                           "(e.g. policy-controller / Kyverno verifyImages) so only "
                           "signed images from your pipeline can be deployed."}


def _rule_verify_failed(s):
    if not s.get("cosign_verify_failed"):
        return None
    img = s.get("cosign_image") or "the image"
    return {"name": "Image signature does not match expected identity/issuer",
            "severity": "MEDIUM", "cvss": "5.3",
            "confidence": "CONFIRMED",
            "cwe": "CWE-347", "owasp": "A08:2021",
            "verified_exploit": True,
            "evidence": f"A Sigstore signature exists for {img}, but keyless "
                        f"verification against the supplied policy FAILED. "
                        f"Expected identity '{s.get('cosign_identity_used_id') or '(supplied)'}'. "
                        f"cosign output: {s.get('cosign_verify_stderr') or 'signature did not match the expected certificate identity/issuer'}",
            "remediation": "Investigate why the signing identity differs from the "
                           "expected build identity/issuer. A mismatch can indicate "
                           "a re-signed or substituted image, a misconfigured "
                           "verification policy, or a pipeline-identity change. "
                           "Re-issue signatures from the canonical pipeline and "
                           "align the admission policy to that identity."}


def _rule_signed_unverified(s):
    # Signature present but no identity policy supplied -> informational only.
    if s.get("cosign_signature_present") is not True:
        return None
    if s.get("cosign_identity_supplied"):
        return None
    if s.get("cosign_verified") is not None or s.get("cosign_verify_failed"):
        return None
    img = s.get("cosign_image") or "the image"
    return {"name": "cosign_signature_verify: image is Sigstore-signed (full trust verify not performed)",
            "severity": "INFO",
            "evidence": f"{img} has a Sigstore signature artifact present in the "
                        "registry, but no certificate identity policy was supplied, "
                        "so the signer's trust could not be fully verified.",
            "remediation": "Supply certificate_identity + certificate_oidc_issuer "
                           "matching your build pipeline to perform full keyless "
                           "trust verification against the expected signer.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_verified_positive(s):
    if s.get("cosign_verified") is not True:
        return None
    img = s.get("cosign_image") or "the image"
    return {"name": "Image signature verified against expected identity (keyless Sigstore)",
            "severity": "POSITIVE",
            "evidence": f"cosign verified {img} against the supplied certificate "
                        "identity and OIDC issuer (keyless Sigstore/Fulcio). The "
                        "image is cryptographically attributed to the expected "
                        "build pipeline.",
            "remediation": "Continue enforcing signature verification at admission "
                           "and keep the verification policy pinned to the canonical "
                           "build identity.",
            "cwe": "N/A", "owasp": "N/A"}


COSIGN_SIGNATURE_VERIFY_FINDING_RULES = [
    _rule_no_input,
    _rule_binary_missing,
    _rule_error,
    _rule_unsigned_image,
    _rule_verify_failed,
    _rule_signed_unverified,
    _rule_verified_positive,
]


INTEL_FIELDS = [("Image reference", "cosign_image"),
                ("Signature ref", "cosign_sig_ref"),
                ("Signature present", "cosign_signature_present"),
                ("Identity policy supplied", "cosign_identity_supplied"),
                ("Trust verified", "cosign_verified"),
                ("Verification failed", "cosign_verify_failed")]


@router.post("/api/supply_chain/cosign_signature_verify")
async def supply_chain_cosign_signature_verify(req: CosignVerifyRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="cosign_signature_verify",
        gather_func=_make_gather(req),
        finding_rules=COSIGN_SIGNATURE_VERIFY_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
