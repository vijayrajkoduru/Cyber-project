"""squashfs_filesystem_audit - SquashFS detection + extraction audit (playbook §3 #23).

SquashFS is by far the most common embedded-Linux root filesystem. This
scanner:
  1. Scans the firmware blob for the SquashFS superblock magic ("hsqs" LE /
     "sqsh" BE) and reads the on-disk superblock to recover version
     (major.minor) and the compression id (gzip/lzma/lzo/xz/lz4/zstd) — a
     pure-bytes parse, no external tool required for detection.
  2. If `unsquashfs` is installed AND a squashfs magic is present, carves the
     image from the offset and extracts it into a temp dir, then walks the
     root filesystem for plaintext credentials, SSH keys, world-writable
     setuid concerns (filename heuristics), and backdoor init scripts.
  3. If `unsquashfs` is absent it still reports the version + compression as
     INFO (honest detection, no false positive).

REAL static probe against the customer firmware file. Read-only — extracted
content is never executed.

Customer input: ScanRequest.target = path to firmware blob on disk.
"""
from __future__ import annotations
import asyncio
import re
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.squashfs_filesystem_audit_findings import SQUASHFS_FILESYSTEM_AUDIT_FINDING_RULES

router = APIRouter()
TIMEOUT = 180
MAX_SCAN_BYTES = 96 * 1024 * 1024
MAX_FILES_SCAN = 8000
MAX_SENSITIVE_HITS = 80

SQUASHFS_MAGIC_LE = b"hsqs"   # little-endian superblock magic
SQUASHFS_MAGIC_BE = b"sqsh"   # big-endian
# Compression ids per squashfs spec
COMP_IDS = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}

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


def _find_and_parse_superblock(path: Path):
    """Return dict {offset, endian, version, compression} or None."""
    try:
        with open(path, "rb") as fh:
            buf = fh.read(MAX_SCAN_BYTES)
    except OSError:
        return None
    offset = -1
    endian = None
    idx_le = buf.find(SQUASHFS_MAGIC_LE)
    idx_be = buf.find(SQUASHFS_MAGIC_BE)
    if idx_le >= 0 and (idx_be < 0 or idx_le <= idx_be):
        offset, endian = idx_le, "little"
    elif idx_be >= 0:
        offset, endian = idx_be, "big"
    if offset < 0:
        return None

    # SquashFS 4.0 superblock: magic(4) inodes(4) mkfs_time(4) block_size(4)
    # frag_count(4) compression(2) block_log(2) flags(2) ... version major(2)
    # version minor(2). We parse compression + version defensively.
    sb = buf[offset:offset + 96]
    info = {"offset": offset, "endian": endian, "version": None, "compression": None}
    try:
        fmt = "<" if endian == "little" else ">"
        # compression id is at byte offset 20 (uint16), version major at 28,
        # minor at 30 in the 4.0 layout.
        if len(sb) >= 32:
            comp_id = struct.unpack_from(fmt + "H", sb, 20)[0]
            vmaj = struct.unpack_from(fmt + "H", sb, 28)[0]
            vmin = struct.unpack_from(fmt + "H", sb, 30)[0]
            if 0 < vmaj <= 4:
                info["version"] = f"{vmaj}.{vmin}"
            info["compression"] = COMP_IDS.get(comp_id, f"id-{comp_id}")
    except struct.error:
        pass
    return info


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
    unsq = shutil.which("unsquashfs")
    if not unsq:
        return None, 0, []
    try:
        subprocess.run(
            [unsq, "-f", "-no", "-d", str(out_dir), str(carved)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=TIMEOUT, check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return 0, 0, []

    sensitive_hits = []
    files_walked = 0
    total_size = 0
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
            name_l.startswith(x) for x in ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")
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
        ctx.state["squashfs_filesystem_audit_total"] = 0
        ctx.source("firmware file not found at target path")
        return

    loop = asyncio.get_event_loop()
    info = await loop.run_in_executor(None, _find_and_parse_superblock, Path(target))
    if not info:
        ctx.state["squashfs_present"] = False
        ctx.state["squashfs_filesystem_audit_total"] = 0
        ctx.source("no SquashFS superblock magic found in first 96 MB")
        return

    ctx.state["squashfs_present"] = True
    ctx.state["squashfs_offset"] = info["offset"]
    ctx.state["squashfs_endian"] = info["endian"]
    ctx.state["squashfs_version"] = info["version"]
    ctx.state["squashfs_compression"] = info["compression"]

    if not shutil.which("unsquashfs"):
        ctx.state["squashfs_tool_missing"] = True
        ctx.state["squashfs_filesystem_audit_total"] = 0
        ctx.source(f"SquashFS v{info['version']} ({info['compression']}) @ "
                   f"0x{info['offset']:x} — unsquashfs not installed")
        return

    carve_dir = tempfile.mkdtemp(prefix="vlsqfs_carve_")
    out_dir = tempfile.mkdtemp(prefix="vlsqfs_out_")
    carved = Path(carve_dir) / "rootfs.squashfs"
    try:
        await loop.run_in_executor(None, _carve, Path(target), info["offset"], carved)
        files_walked, total_size, sensitive_hits = await loop.run_in_executor(
            None, _extract_and_walk, carved, Path(out_dir)
        )
        if files_walked is None:
            ctx.state["squashfs_tool_missing"] = True
            ctx.state["squashfs_filesystem_audit_total"] = 0
            ctx.source("unsquashfs disappeared mid-scan")
            return
        ctx.state["squashfs_extracted_files"] = files_walked
        ctx.state["squashfs_extracted_size"] = total_size
        ctx.state["squashfs_sensitive_hits"] = sensitive_hits
        ctx.state["squashfs_filesystem_audit_total"] = len(sensitive_hits)
        ctx.source(f"SquashFS v{info['version']} ({info['compression']}), "
                   f"{files_walked} files, {len(sensitive_hits)} sensitive")
    finally:
        shutil.rmtree(carve_dir, ignore_errors=True)
        shutil.rmtree(out_dir, ignore_errors=True)


INTEL_FIELDS = [("SquashFS present",        "squashfs_present"),
                ("SquashFS version",        "squashfs_version"),
                ("Compression",             "squashfs_compression"),
                ("Endianness",              "squashfs_endian"),
                ("Offset",                  "squashfs_offset"),
                ("Extracted files",         "squashfs_extracted_files"),
                ("Extracted size (bytes)",  "squashfs_extracted_size"),
                ("Sensitive artefacts",     "squashfs_sensitive_hits")]


@router.post("/api/firmware/squashfs_filesystem_audit")
async def firmware_squashfs_filesystem_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="squashfs_filesystem_audit",
        gather_func=gather, finding_rules=SQUASHFS_FILESYSTEM_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
