"""secure_boot_chain_audit - signed-boot / integrity-verification posture (playbook §5 #45).

Statically inspects the firmware blob for evidence of a verified-boot /
integrity chain and reports what protections are (and are NOT) present:

  - Image signature blocks     : PKCS#7/CMS, RSA `signature {` FIT node,
                                  Android boot image AVB / verified-boot
                                  ("AVB0", "androidboot.vbmeta"), `vbmeta`.
  - dm-verity                   : root-hash verification of the rootfs
                                  ("dm-verity", "veritysetup", "verity").
  - Embedded certificates/keys  : X.509 cert markers, PEM public keys used as
                                  trust anchors.
  - U-Boot verified boot        : CONFIG_FIT_SIGNATURE / required `signature`.

ZERO-FP: this scanner reports POSITIVE when verification evidence is present,
and a graded MEDIUM "no integrity verification" finding ONLY when the blob
shows zero signature/verity/AVB evidence across all markers (a confirmed
absence on a non-trivial image). All marker presence is reported as concrete
evidence — never inferred.

REAL static probe against the customer firmware file.

Customer input: ScanRequest.target = path to firmware blob on disk.
"""
from __future__ import annotations
import asyncio
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.secure_boot_chain_audit_findings import SECURE_BOOT_CHAIN_AUDIT_FINDING_RULES

router = APIRouter()
MAX_BYTES = 128 * 1024 * 1024
MIN_NONTRIVIAL = 64 * 1024     # don't flag absence on a tiny stub

# Signature / verified-boot markers (bytes)
MARKERS = {
    "fit_signature_node":   re.compile(rb"signature\s*\{"),
    "pkcs7_cms":            re.compile(rb"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02"),  # CMS signedData OID
    "android_avb":          re.compile(rb"AVB0|androidboot\.vbmeta|vbmeta", re.I),
    "android_bootsig":      re.compile(rb"BOOT_SIGNATURE|/boot_signature"),
    "dm_verity":            re.compile(rb"dm-verity|veritysetup|\bverity\b", re.I),
    "x509_cert":            re.compile(rb"-----BEGIN CERTIFICATE-----"),
    "pem_pubkey":           re.compile(rb"-----BEGIN PUBLIC KEY-----|-----BEGIN RSA PUBLIC KEY-----"),
    "uboot_fit_required":   re.compile(rb"CONFIG_FIT_SIGNATURE|required.{0,20}conf|required.{0,20}image", re.I),
    "rsa_sha256_oid":       re.compile(rb"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b"),  # sha256WithRSA
    "secure_boot_str":      re.compile(rb"secure[_ ]?boot|SecureBoot", re.I),
}

# Which markers count as *real* verified-boot evidence (vs merely a cert present)
VERIFY_EVIDENCE = ("fit_signature_node", "pkcs7_cms", "android_avb", "android_bootsig",
                   "dm_verity", "uboot_fit_required", "rsa_sha256_oid")


def _scan(path: Path):
    try:
        size = path.stat().st_size
        with open(path, "rb") as fh:
            data = fh.read(MAX_BYTES)
    except OSError as e:
        return None, str(e)
    present = {}
    for name, pat in MARKERS.items():
        if pat.search(data):
            present[name] = True
    return {"present": present, "size": size}, ""


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target or not Path(target).is_file():
        ctx.state["secure_boot_chain_audit_total"] = 0
        ctx.source("firmware file not found at target path")
        return

    res, err = await asyncio.get_event_loop().run_in_executor(None, _scan, Path(target))
    if res is None:
        ctx.state["secure_boot_chain_audit_error"] = f"read failed: {err[:120]}"
        ctx.source("read failed")
        return

    present = res["present"]
    size = res["size"]
    verify_markers = [m for m in VERIFY_EVIDENCE if present.get(m)]
    has_verification = bool(verify_markers)
    has_dm_verity = bool(present.get("dm_verity"))
    has_certs = bool(present.get("x509_cert") or present.get("pem_pubkey"))

    ctx.state["sb_markers_present"] = sorted(present.keys())
    ctx.state["sb_verify_markers"] = verify_markers
    ctx.state["sb_has_verification"] = has_verification
    ctx.state["sb_has_dm_verity"] = has_dm_verity
    ctx.state["sb_has_certs"] = has_certs
    ctx.state["sb_image_size"] = size

    # Graded "no verification" only on a confirmed absence over a non-trivial image
    no_verification = (not has_verification) and size >= MIN_NONTRIVIAL
    ctx.state["sb_no_verification"] = no_verification
    ctx.state["secure_boot_chain_audit_total"] = 1 if no_verification else 0
    ctx.source(f"verify-evidence={verify_markers or 'none'}, dm-verity={has_dm_verity}, "
               f"certs={has_certs}, size={size}")


INTEL_FIELDS = [("Markers present",          "sb_markers_present"),
                ("Verified-boot evidence",   "sb_verify_markers"),
                ("Has verification chain",   "sb_has_verification"),
                ("dm-verity present",        "sb_has_dm_verity"),
                ("Embedded certs/keys",      "sb_has_certs"),
                ("Image size (bytes)",       "sb_image_size")]


@router.post("/api/firmware/secure_boot_chain_audit")
async def firmware_secure_boot_chain_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="secure_boot_chain_audit",
        gather_func=gather, finding_rules=SECURE_BOOT_CHAIN_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
