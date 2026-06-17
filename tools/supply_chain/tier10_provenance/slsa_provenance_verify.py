"""slsa_provenance_verify - SLSA build provenance verification (playbook §5 #59 + #64).

UPGRADES the previously advisory-only "verify SLSA provenance" technique into a
REAL, read-only check that runs whenever the customer supplies an OCI image
reference. Two safe steps, no writes, no exploitation, no chaining:

  STEP 1  Provenance-attestation DISCOVERY via cosign (always observable):
          `cosign verify-attestation <image> --type slsaprovenance
           --certificate-identity-regexp .* --certificate-oidc-issuer-regexp .*`
          rc==0 with output  => a SLSA provenance attestation EXISTS.
          "no matching attestations" => provenance is definitively ABSENT.
          auth / network / unknown error => INFO (never a graded finding).

  STEP 2  FULL verification via slsa-verifier (only when it is installed AND the
          customer supplies source_uri):
          `slsa-verifier verify-image <image> --source-uri <source_uri>
           [--builder-id <builder_id>]`
          rc==0 => provenance verifies against the expected source.
          rc!=0 => provenance present but does NOT verify => real finding.
          slsa-verifier missing => skip step 2, fall back to step-1 discovery.

ZERO-FALSE-POSITIVE policy: a no-provenance finding is emitted ONLY when cosign
DEFINITIVELY reports no matching attestations — never on auth/network/registry
errors (those degrade to INFO). cosign IS installed in the backend image;
slsa-verifier may NOT be — both degrade gracefully.

This is detection only (VA): discovery + verification, no registry/artifact
mutation, no signing, no chaining.

Customer input: req.image_ref (preferred) or req.target if it looks like an OCI
image reference. Optional: source_uri + builder_id for full verification.
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
TIMEOUT = 90


class SlsaVerifyRequest(ScanRequest):
    """ScanRequest + the two extra inputs full verification needs.

    The orchestrator spreads per-scanner options into top-level body keys, so
    source_uri / builder_id arrive as plain fields (ScanRequest has no
    `options` bag)."""
    source_uri: Optional[str] = None
    builder_id: Optional[str] = None


def _looks_like_image_ref(value: str) -> bool:
    """True if `value` reads as an OCI image reference rather than a URL/host.

    An image ref has a '/' (registry/repo) and is NOT an http(s) URL. We keep
    this conservative: a bare hostname ("example.com") is NOT treated as an
    image, so target-only web scans never trip provenance discovery."""
    if not value:
        return False
    v = value.strip()
    if v.startswith(("http://", "https://", "git@", "git+")):
        return False
    if " " in v:
        return False
    return "/" in v


async def _run(cmd: list) -> tuple[int, str, str]:
    """Run a subprocess (read-only) with a hard timeout. Returns (rc, out, err).
    rc == -1 on launch failure, -2 on timeout."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except Exception as e:
        return -1, "", f"launch error: {str(e)[:160]}"
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return -2, "", f"timeout after {TIMEOUT}s"
    return (proc.returncode,
            (out or b"").decode("utf-8", errors="ignore"),
            (err or b"").decode("utf-8", errors="ignore"))


def _tail(text: str, n: int = 400) -> str:
    t = (text or "").strip()
    return t[-n:] if len(t) > n else t


# Phrases that PROVE cosign found no provenance attestation (definitive absence).
_NO_ATTEST_MARKERS = (
    "no matching attestations",
    "no matching signatures",
    "no signatures found",
    "no attestations",
)
# Phrases that mean "could not determine" (auth / network / registry) -> INFO.
_AMBIGUOUS_MARKERS = (
    "unauthorized", "authentication required", "denied", "forbidden",
    "no such host", "connection refused", "timeout", "i/o timeout",
    "dial tcp", "tls", "x509", "certificate", "rate limit", "manifest unknown",
    "name unknown", "not found", "404", "could not", "error reading",
    "getting signed", "fetching", "resolve",
)


def _make_gather(req: SlsaVerifyRequest):
    async def gather(ctx: ScanContext):
        # ── resolve the image reference ─────────────────────────────────
        image = (getattr(req, "image_ref", None) or "").strip()
        if not image:
            tgt = (ctx.host or "").strip()
            if _looks_like_image_ref(tgt):
                image = tgt
        if not image:
            ctx.state["slsa_no_input"] = True
            ctx.source("image_ref required")
            return

        ctx.state["slsa_image"] = image
        src_uri = (getattr(req, "source_uri", None) or "").strip()
        builder_id = (getattr(req, "builder_id", None) or "").strip()
        ctx.state["slsa_source_uri_supplied"] = bool(src_uri)
        if src_uri:
            ctx.state["slsa_source_uri"] = src_uri
        if builder_id:
            ctx.state["slsa_builder_id"] = builder_id

        # ── STEP 1: provenance-attestation discovery via cosign ─────────
        if not (shutil.which("cosign") or COSIGN_BIN):
            ctx.state["slsa_cosign_missing"] = True
            ctx.source("cosign missing")
            return

        rc, out, err = await _run([
            COSIGN_BIN, "verify-attestation", image,
            "--type", "slsaprovenance",
            "--certificate-identity-regexp", ".*",
            "--certificate-oidc-issuer-regexp", ".*",
        ])
        ctx.source("cosign verify-attestation")
        blob = f"{out}\n{err}".lower()

        if rc == 0 and out.strip():
            # cosign returned an attestation bundle -> provenance EXISTS.
            ctx.state["slsa_attestation_present"] = True
            ctx.source("slsa provenance attestation found")
        elif rc in (-1, -2):
            # launch failure / timeout -> ambiguous, never a graded finding.
            ctx.state["slsa_error"] = _tail(err) or "cosign did not complete"
        elif any(m in blob for m in _NO_ATTEST_MARKERS) and not any(
                m in blob for m in _AMBIGUOUS_MARKERS):
            # Definitive absence: cosign explicitly reports no attestations and
            # the output carries no auth/network ambiguity.
            ctx.state["slsa_attestation_present"] = False
            ctx.source("no slsa provenance attestation")
        else:
            # Anything else (auth, registry, network, unknown rc) -> INFO only.
            ctx.state["slsa_error"] = _tail(err) or _tail(out) or f"cosign rc={rc}"

        # ── STEP 2: full verification via slsa-verifier (optional) ──────
        slsa_verifier_bin = shutil.which("slsa-verifier")
        ctx.state["slsa_verifier_available"] = bool(slsa_verifier_bin)

        if not slsa_verifier_bin:
            ctx.state["slsa_step2_skipped"] = "slsa-verifier not installed"
            return
        if not src_uri:
            ctx.state["slsa_step2_skipped"] = "source_uri not supplied"
            return
        # Only attempt full verify when provenance is plausibly present.
        if ctx.state.get("slsa_attestation_present") is False:
            ctx.state["slsa_step2_skipped"] = "no provenance attestation to verify"
            return

        cmd = [slsa_verifier_bin, "verify-image", image, "--source-uri", src_uri]
        if builder_id:
            cmd += ["--builder-id", builder_id]
        vrc, vout, verr = await _run(cmd)
        ctx.source("slsa-verifier verify-image")

        if vrc == 0:
            ctx.state["slsa_verified"] = True
            ctx.source("slsa provenance verified")
        elif vrc in (-1, -2):
            ctx.state["slsa_error"] = _tail(verr) or "slsa-verifier did not complete"
        else:
            # slsa-verifier ran and the provenance did NOT verify against the
            # expected source -> real, confirmed finding.
            ctx.state["slsa_verified"] = False
            ctx.state["slsa_verify_failed"] = True
            ctx.state["slsa_verify_stderr"] = _tail(verr) or _tail(vout) or f"rc={vrc}"
    return gather


# ───────────────────────── finding rules (inline) ─────────────────────────

def _rule_no_input(s):
    if not s.get("slsa_no_input"):
        return None
    return {"name": "slsa_provenance_verify: image_ref required",
            "severity": "INFO",
            "evidence": "No OCI image reference was supplied. Provide "
                        "image_ref=registry/repo:tag (or a target that looks like "
                        "an image reference) to discover SLSA build provenance.",
            "remediation": "Re-run with image_ref set to the container image you "
                           "want to check for SLSA build provenance.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_tools_missing(s):
    if not s.get("slsa_cosign_missing"):
        return None
    return {"name": "slsa_provenance_verify: cosign not available",
            "severity": "INFO",
            "evidence": f"cosign is required for provenance-attestation discovery "
                        f"but was not found for image '{s.get('slsa_image')}'.",
            "remediation": "Install cosign (sigstore) in the scanner environment to "
                           "enable SLSA provenance discovery.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_error(s):
    # Ambiguous auth/network/registry condition -> INFO, never graded.
    err = s.get("slsa_error")
    if not err:
        return None
    # Don't double-report when a definitive result was also reached.
    if s.get("slsa_attestation_present") is True or s.get("slsa_verify_failed"):
        return None
    return {"name": "slsa_provenance_verify: provenance status indeterminate",
            "severity": "INFO",
            "evidence": f"Could not conclusively determine SLSA provenance for "
                        f"'{s.get('slsa_image')}': {err}. This is an access/registry/"
                        "network condition, not a confirmed absence of provenance.",
            "remediation": "Confirm the image reference is correct and the registry "
                           "is reachable (and that pull credentials, if needed, are "
                           "available), then re-run.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_no_provenance(s):
    # Only when cosign DEFINITIVELY reported no attestation (False, not None).
    if s.get("slsa_attestation_present") is not False:
        return None
    return {"name": "Container image has no SLSA build provenance attestation",
            "severity": "LOW", "cvss": "3.7",
            "confidence": "SUSPECTED",
            "cwe": "CWE-1357", "owasp": "A08:2021",
            "verified_exploit": False,
            "evidence": f"cosign found no SLSA provenance attestation for image "
                        f"'{s.get('slsa_image')}'. Consumers cannot cryptographically "
                        "establish how, where, or from what source this image was "
                        "built, so a tampered or substituted build cannot be detected.",
            "remediation": "Emit SLSA provenance from the build (e.g. GitHub's SLSA "
                           "provenance generator, or `cosign attest --type "
                           "slsaprovenance`) and publish the attestation alongside the "
                           "image so consumers can verify build origin."}


def _rule_provenance_verify_failed(s):
    if not s.get("slsa_verify_failed"):
        return None
    return {"name": "SLSA provenance present but fails verification against expected source",
            "severity": "MEDIUM", "cvss": "5.3",
            "confidence": "CONFIRMED",
            "cwe": "CWE-345", "owasp": "A08:2021",
            "verified_exploit": True,
            "evidence": f"slsa-verifier could not verify image "
                        f"'{s.get('slsa_image')}' against source-uri "
                        f"'{s.get('slsa_source_uri')}'. The build provenance does not "
                        f"match the expected source. slsa-verifier output: "
                        f"{s.get('slsa_verify_stderr')}",
            "remediation": "Treat this image as untrusted until reconciled. Confirm "
                           "the expected source-uri/builder-id, rebuild from the "
                           "trusted source so provenance attests to it, and block "
                           "deployment of artifacts whose provenance does not verify."}


def _rule_provenance_present_unverified(s):
    if s.get("slsa_attestation_present") is not True:
        return None
    if s.get("slsa_verified") is True:
        return None  # covered by the POSITIVE rule
    if s.get("slsa_verify_failed"):
        return None  # covered by the MEDIUM rule
    why = s.get("slsa_step2_skipped") or "full verification was not performed"
    return {"name": "SLSA provenance attestation present (not fully verified)",
            "severity": "INFO",
            "evidence": f"A SLSA provenance attestation exists for image "
                        f"'{s.get('slsa_image')}', but full verification was not "
                        f"completed ({why}). Supply source_uri and install "
                        "slsa-verifier for full source-to-build verification.",
            "remediation": "Re-run with source_uri (and optionally builder_id) and "
                           "slsa-verifier installed to fully verify the provenance "
                           "against the expected source.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_verified_positive(s):
    if s.get("slsa_verified") is not True:
        return None
    return {"name": "SLSA build provenance verified against expected source",
            "severity": "POSITIVE",
            "evidence": f"slsa-verifier verified image '{s.get('slsa_image')}' "
                        f"against source-uri '{s.get('slsa_source_uri')}'"
                        + (f" (builder-id '{s.get('slsa_builder_id')}')"
                           if s.get("slsa_builder_id") else "")
                        + ". The image carries cryptographically verifiable build "
                          "provenance attesting to its source.",
            "remediation": "Keep enforcing provenance verification in the deployment "
                           "pipeline; require verified provenance before promotion.",
            "cwe": "N/A", "owasp": "N/A"}


SLSA_PROVENANCE_VERIFY_FINDING_RULES = [
    _rule_no_input,
    _rule_tools_missing,
    _rule_error,
    _rule_no_provenance,
    _rule_provenance_verify_failed,
    _rule_provenance_present_unverified,
    _rule_verified_positive,
]


INTEL_FIELDS = [
    ("Image ref", "slsa_image"),
    ("Provenance attestation present", "slsa_attestation_present"),
    ("Verified", "slsa_verified"),
    ("Verification failed", "slsa_verify_failed"),
    ("slsa-verifier available", "slsa_verifier_available"),
    ("Source URI supplied", "slsa_source_uri_supplied"),
    ("Source URI", "slsa_source_uri"),
    ("Builder ID", "slsa_builder_id"),
    ("Full-verify skipped", "slsa_step2_skipped"),
]


@router.post("/api/supply_chain/slsa_provenance_verify")
async def supply_chain_slsa_provenance_verify(
        req: SlsaVerifyRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="slsa_provenance_verify",
        gather_func=_make_gather(req),
        finding_rules=SLSA_PROVENANCE_VERIFY_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
