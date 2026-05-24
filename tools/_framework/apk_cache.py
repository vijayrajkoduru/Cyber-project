"""Shared APK / IPA decompile cache for binary-static modules.

Problem: 12 isolated scanners shouldn't each decompile the same APK
(12 × 30s = 6 min wasted per scan).

Solution: a SHARED CACHE that lives outside the scanners. First call
triggers the actual decompile; subsequent calls return the cached dir.

Scanners stay isolated — they don't know the cache exists, they just
call `get_unpacked(apk_path)`. If the cache fails, the helper falls
back to a fresh decompile (the scanner sees no difference).

Cache key = SHA256(file contents). Cache TTL = 1 hour.
Storage = /tmp/vl_apk_cache/<sha256>/

Public API:
    get_unpacked(apk_path) -> Path
        Returns directory containing unpacked APK contents.
        Raises FileNotFoundError if apk_path doesn't exist.
        Raises RuntimeError if apktool / unzip not available.

    clear_cache(older_than_seconds=3600)
        Cron-style cleanup. Default: clears entries older than 1 hour.

    cache_dir()
        Returns the cache root path (for debugging / monitoring).
"""
from __future__ import annotations
import hashlib
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Optional

# Cache root — tmpfs on most Linux, ephemeral on Docker restart
CACHE_ROOT = Path(tempfile.gettempdir()) / "vl_apk_cache"
CACHE_ROOT.mkdir(parents=True, exist_ok=True)

DEFAULT_TTL_SECONDS = 3600   # 1 hour
DECOMPILE_TIMEOUT_S = 120    # apktool can be slow on large APKs


def _sha256_file(path: Path) -> str:
    """Stream-hash a file. Used as the cache key."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):  # 1 MB chunks
            h.update(chunk)
    return h.hexdigest()


def _detect_binary_kind(path: Path) -> str:
    """Return 'apk', 'ipa', 'jar', or 'unknown' based on file magic + extension."""
    suf = path.suffix.lower()
    if suf == ".apk":
        return "apk"
    if suf == ".ipa":
        return "ipa"
    if suf in (".jar", ".aar"):
        return "jar"
    # Magic check — APK/IPA/JAR are all ZIP files (PK\x03\x04)
    try:
        with path.open("rb") as f:
            magic = f.read(4)
            if magic[:2] == b"PK":
                # Could be APK or IPA; check for AndroidManifest or Info.plist
                with zipfile.ZipFile(path) as z:
                    names = z.namelist()
                    if any(n.endswith("AndroidManifest.xml") for n in names):
                        return "apk"
                    if any("Payload/" in n and n.endswith("Info.plist") for n in names):
                        return "ipa"
                    return "jar"
    except (zipfile.BadZipFile, OSError):
        pass
    return "unknown"


def _decompile_with_apktool(apk_path: Path, out_dir: Path) -> bool:
    """Try apktool. Returns True on success."""
    if not shutil.which("apktool"):
        return False
    try:
        # apktool d -f -o <out_dir> <apk_path>
        r = subprocess.run(
            ["apktool", "d", "-f", "-o", str(out_dir), str(apk_path)],
            capture_output=True, text=True, timeout=DECOMPILE_TIMEOUT_S,
        )
        return r.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _unpack_with_zipfile(apk_path: Path, out_dir: Path) -> bool:
    """Pure-Python fallback when apktool is unavailable.

    This won't decode binary AndroidManifest.xml, but it WILL unpack
    DEX files, native .so libs, resources, and assets. Scanners that
    only need raw zip contents (secret extraction, endpoint dump) work
    fine with this fallback.
    """
    try:
        with zipfile.ZipFile(apk_path) as z:
            z.extractall(out_dir)
        return True
    except (zipfile.BadZipFile, OSError):
        return False


def get_unpacked(apk_path: str | Path) -> Path:
    """Return a Path to the unpacked directory for the given APK/IPA file.

    First call: actual decompile (cached for 1 hour).
    Subsequent calls: returns the cached directory.

    Raises:
        FileNotFoundError: apk_path doesn't exist or isn't a regular file.
        RuntimeError: decompile failed completely (no tools worked).
    """
    apk = Path(apk_path)
    if not apk.is_file():
        raise FileNotFoundError(f"APK not found: {apk}")

    digest = _sha256_file(apk)
    out_dir = CACHE_ROOT / digest

    # Cache hit
    if out_dir.is_dir() and any(out_dir.iterdir()):
        # Touch the directory so TTL cleanup sees fresh activity
        out_dir.touch(exist_ok=True)
        return out_dir

    # Cache miss — try apktool first, fall back to zipfile
    tmp_dir = out_dir.with_suffix(".tmp")
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir, ignore_errors=True)
    tmp_dir.mkdir(parents=True, exist_ok=True)

    kind = _detect_binary_kind(apk)
    success = False

    if kind == "apk":
        success = _decompile_with_apktool(apk, tmp_dir)
        if not success:
            success = _unpack_with_zipfile(apk, tmp_dir)
    elif kind in ("ipa", "jar"):
        success = _unpack_with_zipfile(apk, tmp_dir)
    else:
        # Unknown format — try unzip anyway
        success = _unpack_with_zipfile(apk, tmp_dir)

    if not success:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError(
            f"Failed to decompile {apk}: apktool and zipfile both failed. "
            f"Detected kind: {kind}"
        )

    # Atomic swap — rename tmp to final cache dir
    if out_dir.exists():
        shutil.rmtree(out_dir, ignore_errors=True)
    tmp_dir.rename(out_dir)
    return out_dir


def clear_cache(older_than_seconds: int = DEFAULT_TTL_SECONDS) -> int:
    """Remove cache entries older than `older_than_seconds`. Returns count removed."""
    if not CACHE_ROOT.is_dir():
        return 0
    cutoff = time.time() - older_than_seconds
    removed = 0
    for entry in CACHE_ROOT.iterdir():
        if not entry.is_dir():
            continue
        try:
            if entry.stat().st_mtime < cutoff:
                shutil.rmtree(entry, ignore_errors=True)
                removed += 1
        except OSError:
            continue
    return removed


def cache_dir() -> Path:
    """Return the cache root path (useful for debugging / monitoring)."""
    return CACHE_ROOT


if __name__ == "__main__":
    # CLI for manual testing: python -m tools._framework.apk_cache <path>
    if len(sys.argv) < 2:
        print(f"usage: python -m tools._framework.apk_cache <apk_path>")
        print(f"cache root: {CACHE_ROOT}")
        sys.exit(2)
    p = Path(sys.argv[1])
    print(f"Decompiling {p}...")
    try:
        d = get_unpacked(p)
        print(f"OK: {d}")
        contents = list(d.iterdir())
        print(f"Contains {len(contents)} top-level entries:")
        for c in contents[:10]:
            print(f"  {c.name}")
    except Exception as e:
        print(f"FAIL: {type(e).__name__}: {e}")
        sys.exit(1)
