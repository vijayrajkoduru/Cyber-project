"""One-shot emoji stripper for the VulnusLab project.

Removes emoji characters from text source files. Conservative on BMP
(only well-known emoji symbol ranges), aggressive on SMP planes.

Run:
    python _strip_emojis.py            # dry-run (report only)
    python _strip_emojis.py --apply    # actually rewrite files
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

EMOJI_RE = re.compile(
    "(?:"
    "[\U0001F000-\U0001FFFF]"        # SMP emoji planes (all emojis here are clearly emojis)
    "|[☀-➿]"               # Misc Symbols + Dingbats (includes ✅ ❌ ⚠ ✨ ❤ ➕)
    "|[⬀-⯿]"               # Arrows + stars (⭐ ⬆ ⬇)
    "|[⏩-⏺]"               # Media controls + alarm clock as emoji
    ")"
    "[️‍⃣\U0001F3FB-\U0001F3FF]*"  # VS16, ZWJ, keycap, skin tones
    "[ ]?"                            # also consume one trailing space (avoids " Recon" leftover)
)

EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".md", ".mdx", ".rst", ".txt",
    ".html", ".htm", ".css", ".scss", ".less",
    ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg",
    ".sh", ".bash", ".ps1", ".bat",
    ".sql", ".env", ".conf",
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", "build", "dist",
    ".next", "venv", ".venv", "env", ".cache", "_archive",
    ".pytest_cache", ".ruff_cache", ".mypy_cache",
    "coverage", ".nyc_output", "out",
}

SKIP_FILES = {
    "_strip_emojis.py",          # don't strip the regex source in this file
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
}


def should_process(path: Path, root: Path) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:
        return False
    if any(part in SKIP_DIRS for part in rel.parts):
        return False
    if path.name in SKIP_FILES:
        return False
    if path.suffix.lower() not in EXTENSIONS:
        return False
    return True


def main(root: Path, apply: bool) -> int:
    affected: list[tuple[Path, int]] = []
    total_emojis = 0
    files_scanned = 0

    for path in root.rglob("*"):
        if not path.is_file() or not should_process(path, root):
            continue
        files_scanned += 1
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError, OSError):
            continue

        matches = EMOJI_RE.findall(text)
        if not matches:
            continue

        total_emojis += len(matches)
        affected.append((path, len(matches)))

        if apply:
            new_text = EMOJI_RE.sub("", text)
            new_text = re.sub(r"[ \t]+(\r?\n)", r"\1", new_text)
            try:
                path.write_text(new_text, encoding="utf-8")
            except (PermissionError, OSError) as e:
                print(f"  ! write failed: {path}: {e}", file=sys.stderr)

    affected.sort(key=lambda x: -x[1])

    print(f"Scanned files       : {files_scanned}")
    print(f"Files with emojis   : {len(affected)}")
    print(f"Total emoji occurrences: {total_emojis}")

    print("\nTop 30 files by emoji count:")
    for p, c in affected[:30]:
        print(f"  {c:6d}  {p.relative_to(root)}")

    if apply:
        print(f"\n[APPLIED] Stripped {total_emojis} emojis from {len(affected)} files.")
    else:
        print(f"\n[DRY-RUN] No changes. Re-run with --apply to write.")
    return 0


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parent
    sys.exit(main(project_root, apply="--apply" in sys.argv))
