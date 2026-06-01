#!/usr/bin/env python3
"""Install VL-FOUNDRY git hooks into .git/hooks/.

Today: pre-commit → runs scripts/pre_commit_score.py to block commits
that drop a module's score by >= 2 points.

Run once after cloning the repo:
  python scripts/install_hooks.py
"""
from __future__ import annotations
import os
import stat
import sys
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

ROOT = Path(__file__).resolve().parent.parent
HOOKS = ROOT / ".git" / "hooks"

# Shim — calls the real hook in scripts/. Cross-platform (Windows uses
# git-bash which understands shebang lines).
PRE_COMMIT = """#!/usr/bin/env bash
# VL-FOUNDRY pre-commit hook — auto-installed by scripts/install_hooks.py
# Bypass with: SKIP_VL_FOUNDRY=1 git commit ...
exec python "$(git rev-parse --show-toplevel)/scripts/pre_commit_score.py"
"""


def main():
    if not HOOKS.exists():
        sys.exit(f"error: {HOOKS} does not exist — is this a git repo?")

    target = HOOKS / "pre-commit"
    if target.exists():
        backup = HOOKS / "pre-commit.before-vl-foundry"
        if not backup.exists():
            target.rename(backup)
            print(f"  backed up existing hook to {backup.name}")
        else:
            target.unlink()
            print(f"  replaced existing hook (backup from earlier install)")

    target.write_text(PRE_COMMIT, encoding="utf-8", newline="\n")
    # chmod +x — needed on Unix; harmless on Windows
    target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    print(f"installed {target.relative_to(ROOT)}")
    print(f"  Test: try committing a change that lowers a module's score.")
    print(f"  Bypass: SKIP_VL_FOUNDRY=1 git commit ...")


if __name__ == "__main__":
    main()
