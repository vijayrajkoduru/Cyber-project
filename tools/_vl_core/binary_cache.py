"""Shared binary unpack/decompile cache for mobile_static scanners.

Each of the 12 scanners would otherwise re-decompile the same APK
(12 × 30s = 6 min wasted). This cache decompiles once, returns the path.

Cache key: SHA-256 of file contents.
Cache root: /tmp/vl_binary_cache/<sha256>/
TTL: 1 hour. Falls back to zipfile if apktool unavailable.

Public API:
    get_unpacked(path)   — returns Path to unpacked dir (decompiles on first call)
    clear_cache(seconds) — removes entries older than `seconds` (default 3600)
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

CACHE_ROOT = Path(tempfile.gettempdir()) / "vl_binary_cache"
CACHE_ROOT.mkdir(parents=True, exist_ok=True)
DECOMPILE_TIMEOUT_S = 120
DEFAULT_TTL_S = 3600


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _detect_kind(path: Path) -> str:
    """Identify binary type by magic + extension. Returns 'apk', 'ipa', 'pe', 'elf', 'macho', 'unknown'."""
    suf = path.suffix.lower()
    try:
        with path.open("rb") as f:
            magic = f.read(8)
    except OSError:
        return "unknown"

    if magic[:2] == b"PK":
        # ZIP-based: APK / IPA / JAR
        try:
            with zipfile.ZipFile(path) as z:
                names = z.namelist()
                if any(n.endswith("AndroidManifest.xml") for n in names):
                    return "apk"
                if any("/Info.plist" in n for n in names) or suf == ".ipa":
                    return "ipa"
                return "jar"
        except (zipfile.BadZipFile, OSError):
            pass
        return "zip"
    if magic[:4] == b"\x7fELF":
        return "elf"
    if magic[:2] == b"MZ":
        return "pe"
    if magic[:4] in (b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return "macho"
    return "unknown"


def _decompile_apktool(apk: Path, out: Path) -> bool:
    if not shutil.which("apktool"):
        return False
    try:
        r = subprocess.run(
            ["apktool", "d", "-f", "-q", "-o", str(out), str(apk)],
            capture_output=True, text=True, timeout=DECOMPILE_TIMEOUT_S,
        )
        return r.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def _unpack_zipfile(archive: Path, out: Path) -> bool:
    try:
        with zipfile.ZipFile(archive) as z:
            z.extractall(out)
        return True
    except (zipfile.BadZipFile, OSError):
        return False


def get_unpacked(path: str | Path) -> Path:
    """Return Path to the unpacked binary directory. Decompiles once, caches.

    Raises FileNotFoundError if path doesn't exist.
    Raises RuntimeError if no unpack method succeeded.
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"binary not found: {p}")

    digest = _sha256_file(p)
    out_dir = CACHE_ROOT / digest

    # Cache hit — return existing
    if out_dir.is_dir() and any(out_dir.iterdir()):
        return out_dir

    # Cache miss — unpack
    tmp = out_dir.with_suffix(".tmp")
    if tmp.exists():
        shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True, exist_ok=True)

    kind = _detect_kind(p)
    ok = False

    if kind == "apk":
        ok = _decompile_apktool(p, tmp)
        if not ok:
            ok = _unpack_zipfile(p, tmp)
    elif kind in ("ipa", "jar", "zip"):
        ok = _unpack_zipfile(p, tmp)
    elif kind in ("elf", "pe", "macho", "unknown"):
        # Single-file binaries — "unpack" means copy to cache dir
        try:
            (tmp / p.name).write_bytes(p.read_bytes())
            ok = True
        except OSError:
            ok = False

    if not ok:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(f"unpack failed for {p} (kind={kind})")

    # Atomic swap
    if out_dir.exists():
        shutil.rmtree(out_dir, ignore_errors=True)
    tmp.rename(out_dir)
    return out_dir


def clear_cache(older_than_seconds: int = DEFAULT_TTL_S) -> int:
    """Remove cache entries older than threshold. Returns count removed."""
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


if __name__ == "__main__":
    # CLI test: python -m tools._framework.binary_cache <path>
    if len(sys.argv) < 2:
        print(f"usage: python -m tools._framework.binary_cache <file>")
        sys.exit(2)
    try:
        d = get_unpacked(sys.argv[1])
        print(f"OK: {d}")
        for c in list(d.iterdir())[:10]:
            print(f"  {c.name}")
    except Exception as e:
        print(f"FAIL: {type(e).__name__}: {e}")
        sys.exit(1)
