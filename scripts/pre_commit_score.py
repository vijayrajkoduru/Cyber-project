#!/usr/bin/env python3
"""VL-FOUNDRY pre-commit gate — blocks commits that lower a module's score.

Runs the scorer against any module whose `tools/<module>/` tree has staged
changes. Compares the post-edit score against the last green score stored
in `.vl-foundry-scores.json` at the repo root.

Behavior:
  • Score went UP or stayed the same  → exit 0 (commit allowed)
  • Score went DOWN by < 2 points     → warn but allow (small regressions
                                          may be intentional during refactors)
  • Score went DOWN by >= 2 points    → exit 1 (commit blocked)

Bypass for an intentional drop:
  $ SKIP_VL_FOUNDRY=1 git commit ...

Install:
  $ ln -s ../../scripts/pre_commit_score.py .git/hooks/pre-commit
  (Windows: copy + chmod +x equivalent)

Or wire into `pre-commit` framework via .pre-commit-config.yaml.
"""
from __future__ import annotations
import json
import os
import subprocess
import sys
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SCORE_LOG = ROOT / ".vl-foundry-scores.json"
ALLOWED_DROP = 2.0  # points — refactors can dip slightly

# Known modules to track. New modules auto-added on first green run.
KNOWN_MODULES = ("recon", "vuln", "webapp", "osint", "exploit",
                 "password", "bof", "pivot", "tunnel", "container_k8s",
                 "webapp", "cloud")


def staged_modules() -> set[str]:
    """Return modules with staged changes under tools/<module>/."""
    try:
        out = subprocess.check_output(
            ["git", "diff", "--cached", "--name-only"],
            cwd=ROOT, text=True
        )
    except subprocess.CalledProcessError:
        return set()
    mods = set()
    for line in out.splitlines():
        parts = line.replace("\\", "/").split("/")
        if len(parts) >= 2 and parts[0] == "tools":
            mod = parts[1]
            if (ROOT / "tools" / mod).is_dir():
                mods.add(mod)
    return mods


def load_score_log() -> dict:
    if SCORE_LOG.exists():
        try:
            return json.loads(SCORE_LOG.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_score_log(data: dict) -> None:
    SCORE_LOG.write_text(json.dumps(data, indent=2), encoding="utf-8")


def current_score(module: str) -> float | None:
    """Run scorer and return the numeric score, or None on error."""
    try:
        from scripts.score_module import score_module
        r = score_module(module, verbose=False)
        if "error" in r:
            return None
        return float(r["score"])
    except Exception as e:
        print(f"  [pre-commit] failed to score {module}: {e}", file=sys.stderr)
        return None


def main():
    if os.environ.get("SKIP_VL_FOUNDRY"):
        print("[pre-commit] SKIP_VL_FOUNDRY set — bypassing VL-FOUNDRY gate")
        sys.exit(0)

    mods = staged_modules() & set(KNOWN_MODULES)
    if not mods:
        sys.exit(0)

    log = load_score_log()
    blocked = False

    for m in sorted(mods):
        new = current_score(m)
        if new is None:
            continue
        old = log.get(m, {}).get("score")
        if old is None:
            # First-time tracking — record and pass
            log[m] = {"score": new}
            print(f"  [pre-commit] {m}: first run, baseline = {new:.1f}")
            continue
        delta = new - old
        if delta >= 0:
            print(f"  [pre-commit] {m}: {old:.1f} → {new:.1f} (+{delta:.1f}) OK")
            log[m] = {"score": new}
        elif abs(delta) < ALLOWED_DROP:
            print(f"  [pre-commit] {m}: {old:.1f} → {new:.1f} ({delta:+.1f}) "
                  f"WARN — small regression allowed")
            log[m] = {"score": new}
        else:
            print(f"  [pre-commit] {m}: {old:.1f} → {new:.1f} ({delta:+.1f}) "
                  f"BLOCKED — drop >= {ALLOWED_DROP}", file=sys.stderr)
            print(f"  Run: python scripts/score_module.py {m} --verbose",
                  file=sys.stderr)
            print(f"  To bypass: SKIP_VL_FOUNDRY=1 git commit ...",
                  file=sys.stderr)
            blocked = True

    save_score_log(log)
    sys.exit(1 if blocked else 0)


if __name__ == "__main__":
    main()
