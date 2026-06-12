"""cpio_archive_extract - carve + extract cpio initramfs (playbook §3 #27).

Many embedded firmwares wrap their root filesystem (or an initramfs) as a
cpio archive — frequently a `newc`/SVR4 ASCII cpio, sometimes gzip-wrapped.
This scanner:
  1. Scans the firmware blob for cpio magic ("070701"/"070702"/"070707"
     ASCII, or the binary 0x71c7 / 0xc771 magic) and detects presence.
  2. If a cpio magic is found AND the `cpio` binary is installed, carves
     from the offset and extracts into a temp dir, then walks the tree for
     sensitive artefacts (shadow/passwd/SSH keys/wpa configs/backdoor rcS).
  3. If `cpio` is not installed it still reports the detected magic +
     offset as INFO (real detection, honest about missing extraction tool).

REAL static probe against the customer-supplied firmware file. No payloads,
no execution of extracted content — read-only filesystem walk only.

Customer input: ScanRequest.target = path to firmware blob on disk.
"""
from __future__ import annotations
import asyncio
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.cpio_archive_extract_findings import CPIO_ARCHIVE_EXTRACT_FINDING_RULES

router = APIRouter()
TIMEOUT = 120
MAX_SCAN_BYTES = 96 * 1024 * 1024     # 96 MB magic-scan window
MAX_FILES_SCAN = 8000
MAX_SENSITIVE_HITS = 80

# ASCII cpio magics (newc=070701, crc=070702, old-ascii=070707)
CPIO_ASCII_MAGICS = (b"070701", b"070702", b"070707")
# Binary (SVR2/old) cpio magic, both byte orders
CPIO_BIN_MAGIC_LE = b"\xc7\x71"
CPIO_BIN_MAGIC_BE = b"\x71\xc7"

OPENSSH_KEY_RE = re.compile(rb"-----BEGIN (OPENSSH|RSA|DSA|EC|PGP) PRIVATE KEY-----")
SHADOW_HASH_RE = re.compile(rb"\$[1356ay]\$[A-Za-z0-9./]{6,}\$[A-Za-z0-9./]{16,}")
TELNETD_BACKDOOR_RE = re.compile(rb"telnetd[^\n]{0,80}-l[^\n]{0,80}/bin/sh", re.I)

SENSITIVE_NAMES = {
    "shadow", "passwd", "gshadow", "master.passwd",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "authorized_keys", "known_hosts",
    "ssh_host_rsa_key", "ssh_host_dsa_key", "ssh_host_ecdsa_key", "ssh_host_ed25519_key",
    "wpa_supplicant.conf", "hostapd.conf", "telnetd.conf",
    "rcS", "inittab", ".netrc",
}


def _find_cpio_offset(path: Path):
    """Return (offset, magic_label) of first cpio magic, or (-1, None)."""
    try:
        with open(path, "rb") as fh:
            buf = fh.read(MAX_SCAN_BYTES)
    except OSError:
        return -1, None
    best = -1
    label = None
    for magic in CPIO_ASCII_MAGICS:
        idx = buf.find(magic)
        if idx >= 0 and (best < 0 or idx < best):
            best, label = idx, magic.decode("ascii")
    # Binary magic must be 2-byte aligned-ish; only accept if earlier than ascii
    for magic, name in ((CPIO_BIN_MAGIC_LE, "0x71c7"), (CPIO_BIN_MAGIC_BE, "0xc771")):
        idx = buf.find(magic)
        if idx >= 0 and (best < 0 or idx < best):
            best, label = idx, name
    return best, label


def _carve(path: Path, offset: int, dst: Path):
    try:
        with open(path, "rb") as src, open(dst, "wb") as out:
            src.seek(offset)
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
    except OSError:
        pass


def _extract_and_walk(carved: Path, out_dir: Path):
    """Run `cpio -idmv` inside out_dir reading carved file. Returns
    (files_walked, total_size, sensitive_hits)."""
    cpio_bin = shutil.which("cpio")
    sensitive_hits = []
    files_walked = 0
    total_size = 0
    if not cpio_bin:
        return None, 0, []
    try:
        # cpio reads the archive on stdin; extract verbosely without restoring
        # ownership. `-D` selects the output directory (GNU cpio).
        with open(carved, "rb") as fh:
            subprocess.run(
                [cpio_bin, "-idm", "--no-absolute-filenames", "-D", str(out_dir)],
                stdin=fh, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=TIMEOUT, check=False,
            )
    except (subprocess.TimeoutExpired, OSError):
        return 0, 0, []

    for p in out_dir.rglob("*"):
        if files_walked >= MAX_FILES_SCAN:
            break
        if not p.is_file():
            continue
        files_walked += 1
        try:
            total_size += p.stat().st_size
        except OSError:
            pass
        rel = str(p.relative_to(out_dir)).replace("\\", "/")
        name_l = p.name.lower()
        kind = None
        if name_l in SENSITIVE_NAMES or any(
            name_l.startswith(s) for s in ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")
        ):
            kind = "sensitive-filename"
        content_kind = None
        try:
            head = p.read_bytes()[:8192]
            if OPENSSH_KEY_RE.search(head):
                content_kind = "openssh-private-key"
            elif SHADOW_HASH_RE.search(head):
                content_kind = "password-hash"
            elif TELNETD_BACKDOOR_RE.search(head):
                content_kind = "telnetd-backdoor-snippet"
        except (OSError, ValueError):
            pass
        hit = content_kind or kind
        if hit and len(sensitive_hits) < MAX_SENSITIVE_HITS:
            try:
                sz = p.stat().st_size
            except OSError:
                sz = 0
            sensitive_hits.append({"path": rel[:240], "size": sz, "kind": hit})
    return files_walked, total_size, sensitive_hits


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target or not Path(target).is_file():
        ctx.state["cpio_archive_extract_total"] = 0
        ctx.source("firmware file not found at target path")
        return

    loop = asyncio.get_event_loop()
    offset, magic = await loop.run_in_executor(None, _find_cpio_offset, Path(target))
    if offset < 0:
        ctx.state["cpio_present"] = False
        ctx.state["cpio_archive_extract_total"] = 0
        ctx.source("no cpio magic found in first 96 MB")
        return

    ctx.state["cpio_present"] = True
    ctx.state["cpio_offset"] = offset
    ctx.state["cpio_magic"] = magic

    if not shutil.which("cpio"):
        # Detection succeeded, extraction tool absent — honest INFO, no FP.
        ctx.state["cpio_tool_missing"] = True
        ctx.state["cpio_archive_extract_total"] = 0
        ctx.source(f"cpio magic {magic} @ 0x{offset:x} (cpio binary not installed)")
        return

    carve_dir = tempfile.mkdtemp(prefix="vlcpio_carve_")
    out_dir = tempfile.mkdtemp(prefix="vlcpio_out_")
    carved = Path(carve_dir) / "archive.cpio"
    try:
        await loop.run_in_executor(None, _carve, Path(target), offset, carved)
        files_walked, total_size, sensitive_hits = await loop.run_in_executor(
            None, _extract_and_walk, carved, Path(out_dir)
        )
        if files_walked is None:
            ctx.state["cpio_tool_missing"] = True
            ctx.state["cpio_archive_extract_total"] = 0
            ctx.source("cpio binary disappeared mid-scan")
            return
        ctx.state["cpio_extracted_files"] = files_walked
        ctx.state["cpio_extracted_size"] = total_size
        ctx.state["cpio_sensitive_hits"] = sensitive_hits
        ctx.state["cpio_archive_extract_total"] = len(sensitive_hits)
        ctx.source(f"cpio @ 0x{offset:x}, {files_walked} files, {len(sensitive_hits)} sensitive")
    finally:
        shutil.rmtree(carve_dir, ignore_errors=True)
        shutil.rmtree(out_dir, ignore_errors=True)


INTEL_FIELDS = [("cpio archive present",   "cpio_present"),
                ("cpio magic",             "cpio_magic"),
                ("cpio offset",            "cpio_offset"),
                ("Extracted files",        "cpio_extracted_files"),
                ("Extracted size (bytes)", "cpio_extracted_size"),
                ("Sensitive artefacts",    "cpio_sensitive_hits")]


@router.post("/api/firmware/cpio_archive_extract")
async def firmware_cpio_archive_extract(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="cpio_archive_extract",
        gather_func=gather, finding_rules=CPIO_ARCHIVE_EXTRACT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
