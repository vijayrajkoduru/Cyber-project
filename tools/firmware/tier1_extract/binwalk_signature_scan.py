"""binwalk_signature_scan - binwalk signature + extract pass (playbook §2 #11/12).

Wraps `binwalk -B <firmware>` for signature scan AND `binwalk -e <firmware>
-C <outdir>` for extraction. Parses stdout for detected filesystem types
(squashfs / JFFS2 / cramfs / UBIFS / cpio / etc.) and inspects the extracted
tree for plaintext credentials (/etc/shadow, /etc/passwd, id_rsa, OpenSSH
private keys, .ssh/, telnetd backdoors).

Customer input: ScanRequest.target = path to firmware blob (uploaded /tmp).
"""
from __future__ import annotations
import asyncio
import re
import shutil
import tempfile
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.binwalk_signature_scan_findings import BINWALK_SIGNATURE_SCAN_FINDING_RULES

router = APIRouter()
TIMEOUT_SIG = 60
TIMEOUT_EXTRACT = 240
MAX_SIG_LINES = 400
MAX_SENSITIVE_HITS = 60

# Filesystem signatures binwalk reports
FS_PATTERNS = [
    ("squashfs",   re.compile(r"\bSquashfs\b", re.I)),
    ("jffs2",      re.compile(r"\bJFFS2\b",    re.I)),
    ("cramfs",     re.compile(r"\bCramFS\b",   re.I)),
    ("ubifs",      re.compile(r"\bUBIFS|UBI image\b", re.I)),
    ("yaffs",      re.compile(r"\bYAFFS\b",    re.I)),
    ("cpio",       re.compile(r"\bASCII cpio archive\b", re.I)),
    ("ext_fs",     re.compile(r"\bLinux EXT filesystem\b", re.I)),
    ("romfs",      re.compile(r"\bRomFS\b",    re.I)),
    ("uboot",      re.compile(r"\buImage header|U-Boot\b", re.I)),
    ("gzip",       re.compile(r"\bgzip compressed\b", re.I)),
    ("lzma",       re.compile(r"\bLZMA compressed\b", re.I)),
    ("zlib",       re.compile(r"\bzlib compressed\b", re.I)),
    ("bzip2",      re.compile(r"\bbzip2 compressed\b", re.I)),
    ("xz",         re.compile(r"\bxz compressed\b", re.I)),
    ("elf",        re.compile(r"\bELF\b",       re.I)),
]

# Plaintext credential markers inside extracted root filesystem
SHADOW_HASH_RE = re.compile(rb"\$[16ay]\$[A-Za-z0-9./]{8,}\$[A-Za-z0-9./]{20,}")
SHADOW_HASH_NEW_RE = re.compile(rb"\$argon2[id]?\$|\$2[abxy]\$\d\d\$|\$y\$")
OPENSSH_KEY_RE = re.compile(rb"-----BEGIN (OPENSSH|RSA|DSA|EC|PGP) PRIVATE KEY-----")
SENSITIVE_FILES = ("shadow", "passwd", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
                   "authorized_keys", "ssh_host_rsa_key", "wpa_supplicant.conf",
                   "hostapd.conf", "telnetd.conf")


async def _run(cmd, timeout):
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode, out.decode("utf-8", errors="replace"), err.decode("utf-8", errors="replace")
    except asyncio.TimeoutError:
        try: proc.kill()
        except Exception: pass
        return -1, "", f"timeout after {timeout}s"


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target or not Path(target).is_file():
        ctx.state["binwalk_signature_scan_total"] = 0
        ctx.source("firmware file not found at target path")
        return
    if not shutil.which("binwalk"):
        ctx.state["binwalk_signature_scan_error"] = "binwalk binary not installed"
        ctx.source("binwalk missing")
        return

    findings = []
    detected_fs = []
    extract_dir = tempfile.mkdtemp(prefix="binwalk_extract_")
    try:
        # 1. Signature scan (binwalk -B)
        rc, sig_out, sig_err = await _run(["binwalk", "-B", target], TIMEOUT_SIG)
        sig_lines = [l for l in sig_out.splitlines() if l.strip() and not l.startswith("DECIMAL")][:MAX_SIG_LINES]
        for label, pat in FS_PATTERNS:
            if pat.search(sig_out):
                detected_fs.append(label)
        if detected_fs:
            findings.append({"check": "filesystems_detected", "labels": detected_fs})

        # 2. Extraction (binwalk -e -C extract_dir)
        rc2, ext_out, ext_err = await _run(
            ["binwalk", "-e", "-q", "-C", extract_dir, target], TIMEOUT_EXTRACT
        )
        extracted_files = 0
        total_size = 0
        sensitive_hits = []
        try:
            base = Path(extract_dir)
            for p in base.rglob("*"):
                if p.is_file():
                    extracted_files += 1
                    try: total_size += p.stat().st_size
                    except OSError: pass
                    name_l = p.name.lower()
                    if any(s in name_l for s in SENSITIVE_FILES):
                        if len(sensitive_hits) < MAX_SENSITIVE_HITS:
                            sensitive_hits.append({"path": str(p.relative_to(base))[:200],
                                                   "size": p.stat().st_size if p.exists() else 0,
                                                   "kind": "sensitive-filename"})
                    # peek shadow + OpenSSH key content (first 4KB)
                    if extracted_files <= 5000 and len(sensitive_hits) < MAX_SENSITIVE_HITS:
                        try:
                            head = p.read_bytes()[:4096]
                            if OPENSSH_KEY_RE.search(head):
                                sensitive_hits.append({"path": str(p.relative_to(base))[:200],
                                                       "kind": "openssh-private-key",
                                                       "size": p.stat().st_size})
                            elif SHADOW_HASH_RE.search(head) or SHADOW_HASH_NEW_RE.search(head):
                                sensitive_hits.append({"path": str(p.relative_to(base))[:200],
                                                       "kind": "password-hash",
                                                       "size": p.stat().st_size})
                        except (OSError, ValueError):
                            pass
        except Exception:
            pass

        if extracted_files > 0:
            findings.append({"check": "extraction_succeeded",
                             "files": extracted_files,
                             "size_bytes": total_size})
        if sensitive_hits:
            findings.append({"check": "sensitive_files_found", "items": sensitive_hits})

        ctx.state["binwalk_detected_fs"] = detected_fs
        ctx.state["binwalk_sig_excerpt"] = sig_lines[:30]
        ctx.state["binwalk_extracted_files"] = extracted_files
        ctx.state["binwalk_extracted_size"] = total_size
        ctx.state["binwalk_sensitive_hits"] = sensitive_hits
        ctx.state["binwalk_signature_scan_total"] = len(findings)
        ctx.source(f"{len(detected_fs)} fs detected, {extracted_files} files extracted, "
                   f"{len(sensitive_hits)} sensitive hits")
    finally:
        try: shutil.rmtree(extract_dir, ignore_errors=True)
        except Exception: pass


INTEL_FIELDS = [("Filesystems detected",      "binwalk_detected_fs"),
                ("Extracted files",           "binwalk_extracted_files"),
                ("Extracted size (bytes)",    "binwalk_extracted_size"),
                ("Sensitive files found",     "binwalk_sensitive_hits"),
                ("Signature excerpt",         "binwalk_sig_excerpt")]


@router.post("/api/firmware/binwalk_signature_scan")
async def firmware_binwalk_signature_scan(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="binwalk_signature_scan",
        gather_func=gather, finding_rules=BINWALK_SIGNATURE_SCAN_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
