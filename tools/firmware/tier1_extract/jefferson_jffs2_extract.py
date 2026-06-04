"""jefferson_jffs2_extract - JFFS2 filesystem extract via jefferson (playbook §3 #24).

Uses the `jefferson` Python module to extract a JFFS2 filesystem from the
firmware blob. After extraction, scans /etc/, /usr/etc/, /lib/firmware/, .ssh/
for sensitive artefacts: shadow, passwd, id_rsa, authorized_keys, wpa_supplicant
configs, hostapd configs, custom backdoor binaries.

Customer input: ScanRequest.target = path to firmware blob.
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
from tools._framework import ScanContext, run_scanner
from tools._payloads.jefferson_jffs2_extract_findings import JEFFERSON_JFFS2_EXTRACT_FINDING_RULES

router = APIRouter()
TIMEOUT = 180
MAX_FILES_SCAN = 6000
MAX_SENSITIVE_HITS = 80

JFFS2_MAGIC = b"\x85\x19"  # JFFS2 little endian (NODE_MAGIC)
JFFS2_BIG_MAGIC = b"\x19\x85"

OPENSSH_KEY_RE = re.compile(rb"-----BEGIN (OPENSSH|RSA|DSA|EC|PGP) PRIVATE KEY-----")
SHADOW_HASH_RE = re.compile(rb"\$[16ay]\$[A-Za-z0-9./]{6,}\$[A-Za-z0-9./]{16,}")
TELNETD_BACKDOOR_RE = re.compile(rb"telnetd[^\n]{0,80}-l[^\n]{0,80}/bin/sh", re.I)

SENSITIVE_NAMES = {
    "shadow", "passwd", "gshadow", "master.passwd",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "authorized_keys", "known_hosts",
    "ssh_host_rsa_key", "ssh_host_dsa_key", "ssh_host_ecdsa_key", "ssh_host_ed25519_key",
    "wpa_supplicant.conf", "hostapd.conf", "telnetd.conf",
    "rcS", "inittab", ".netrc",
}
SENSITIVE_DIRS = ("/etc/", "/usr/etc/", "/lib/firmware/", "/.ssh/", "/root/")


async def _find_jffs2_offset(target: Path) -> int:
    """Scan firmware for first JFFS2 magic offset. Returns -1 if absent."""
    def _scan():
        try:
            with open(target, "rb") as fh:
                buf = fh.read(64 * 1024 * 1024)  # 64 MB cap
            idx_le = buf.find(JFFS2_MAGIC)
            idx_be = buf.find(JFFS2_BIG_MAGIC)
            if idx_le < 0 and idx_be < 0: return -1
            if idx_le < 0: return idx_be
            if idx_be < 0: return idx_le
            return min(idx_le, idx_be)
        except (OSError, ValueError):
            return -1
    return await asyncio.get_event_loop().run_in_executor(None, _scan)


async def _carve(target: Path, offset: int, carve_path: Path):
    def _do():
        try:
            with open(target, "rb") as src, open(carve_path, "wb") as dst:
                src.seek(offset)
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk: break
                    dst.write(chunk)
        except OSError:
            pass
    await asyncio.get_event_loop().run_in_executor(None, _do)


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target or not Path(target).is_file():
        ctx.state["jefferson_jffs2_extract_total"] = 0
        ctx.source("firmware file not found at target path")
        return

    try:
        import jefferson  # noqa: F401
    except ImportError:
        ctx.state["jefferson_jffs2_extract_error"] = "jefferson Python module not installed"
        ctx.source("jefferson missing")
        return

    tpath = Path(target)
    offset = await _find_jffs2_offset(tpath)
    if offset < 0:
        ctx.state["jefferson_jffs2_extract_total"] = 0
        ctx.state["jffs2_present"] = False
        ctx.source("no JFFS2 magic found in first 64 MB")
        return

    findings = []
    out_dir = tempfile.mkdtemp(prefix="jefferson_out_")
    carve_dir = tempfile.mkdtemp(prefix="jefferson_carve_")
    carved = Path(carve_dir) / "jffs2.bin"
    try:
        await _carve(tpath, offset, carved)

        # jefferson CLI: `jefferson <jffs2.bin> -d <out>`
        bin_path = shutil.which("jefferson") or "/usr/local/bin/jefferson"
        cmd = [bin_path, str(carved), "-d", out_dir]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            try:
                _stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
            except asyncio.TimeoutError:
                try: proc.kill()
                except Exception: pass
                ctx.state["jefferson_jffs2_extract_error"] = f"timeout after {TIMEOUT}s"
                ctx.source("timeout")
                return
        except FileNotFoundError:
            ctx.state["jefferson_jffs2_extract_error"] = "jefferson CLI not found"
            ctx.source("jefferson CLI missing")
            return

        # Walk extracted tree
        base = Path(out_dir)
        sensitive_hits = []
        files_walked = 0
        total_size = 0
        for p in base.rglob("*"):
            if files_walked >= MAX_FILES_SCAN: break
            if not p.is_file(): continue
            files_walked += 1
            try: total_size += p.stat().st_size
            except OSError: pass

            rel = str(p.relative_to(base)).replace("\\", "/")
            name_l = p.name.lower()
            kind = None
            if name_l in SENSITIVE_NAMES or any(name_l.startswith(s) for s in ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")):
                kind = "sensitive-filename"
            elif any(d in ("/" + rel).lower() for d in SENSITIVE_DIRS) and (
                "key" in name_l or "secret" in name_l or "passwd" in name_l):
                kind = "sensitive-path"

            # peek content
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

            hit_kind = content_kind or kind
            if hit_kind and len(sensitive_hits) < MAX_SENSITIVE_HITS:
                try: sz = p.stat().st_size
                except OSError: sz = 0
                sensitive_hits.append({"path": rel[:240], "size": sz, "kind": hit_kind})

        if files_walked > 0:
            findings.append({"check": "jffs2_extracted", "files": files_walked,
                             "size_bytes": total_size, "offset": offset})
        if sensitive_hits:
            findings.append({"check": "jffs2_sensitive_artefacts", "items": sensitive_hits})

        ctx.state["jffs2_present"] = True
        ctx.state["jffs2_offset"] = offset
        ctx.state["jffs2_extracted_files"] = files_walked
        ctx.state["jffs2_extracted_size"] = total_size
        ctx.state["jffs2_sensitive_hits"] = sensitive_hits
        ctx.state["jefferson_jffs2_extract_total"] = len(findings)
        ctx.source(f"JFFS2 @ 0x{offset:x}, {files_walked} files, {len(sensitive_hits)} sensitive")
    finally:
        try: shutil.rmtree(out_dir, ignore_errors=True)
        except Exception: pass
        try: shutil.rmtree(carve_dir, ignore_errors=True)
        except Exception: pass


INTEL_FIELDS = [("JFFS2 present",          "jffs2_present"),
                ("JFFS2 offset",           "jffs2_offset"),
                ("Extracted files",        "jffs2_extracted_files"),
                ("Extracted size (bytes)", "jffs2_extracted_size"),
                ("Sensitive artefacts",    "jffs2_sensitive_hits")]


@router.post("/api/firmware/jefferson_jffs2_extract")
async def firmware_jefferson_jffs2_extract(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="jefferson_jffs2_extract",
        gather_func=gather, finding_rules=JEFFERSON_JFFS2_EXTRACT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
