#!/usr/bin/env python3
"""VL-FOUNDRY CI gate — fails the build if any module's forge score regresses.

Unlike the pre-commit hook (`pre_commit_score.py`), this gate:
  • Scores EVERY module recorded in `.vl-foundry-scores.json` — not just the
    ones with staged changes. CI checks the whole tree on every push/PR.
  • Is READ-ONLY. It never rewrites `.vl-foundry-scores.json`; the committed
    file is the source of truth, and CI verifies the current code still meets
    it. (The pre-commit hook is what advances the baselines on commit.)

A module fails the gate when EITHER:
  • current score < recorded baseline − ALLOWED_DROP   (regression), or
  • current score < FLOOR                              (below ship bar)

Usage:
  python scripts/ci_score_gate.py            # gate all tracked modules
  python scripts/ci_score_gate.py --floor 90 # override the absolute floor

Exit code 0 if every module passes, 1 otherwise (CI-friendly).
"""
from __future__ import annotations
import argparse
import json
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
ALLOWED_DROP = 2.0   # points — matches pre_commit_score.py refactor tolerance
DEFAULT_FLOOR = 85.0  # the scorer's "ready to ship" bar (score_module.ready)


def load_baselines() -> dict:
    if not SCORE_LOG.exists():
        print(f"ERROR: {SCORE_LOG.name} not found — nothing to gate against.",
              file=sys.stderr)
        sys.exit(1)
    try:
        return json.loads(SCORE_LOG.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"ERROR: cannot parse {SCORE_LOG.name}: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser(description="VL-FOUNDRY CI score gate")
    ap.add_argument("--floor", type=float, default=DEFAULT_FLOOR,
                    help=f"absolute minimum score per module (default {DEFAULT_FLOOR})")
    ap.add_argument("--allowed-drop", type=float, default=ALLOWED_DROP,
                    help=f"tolerated regression below baseline (default {ALLOWED_DROP})")
    args = ap.parse_args()

    # Import after sys.path tweak so `scripts` package resolves in CI.
    from scripts.score_module import score_module

    baselines = load_baselines()
    if not baselines:
        print(f"ERROR: {SCORE_LOG.name} is empty — no modules to gate.",
              file=sys.stderr)
        sys.exit(1)

    failures: list[str] = []
    print(f"VL-FOUNDRY CI gate — {len(baselines)} modules "
          f"(floor={args.floor:.1f}, allowed drop={args.allowed_drop:.1f})\n")

    for module in sorted(baselines):
        old = baselines[module].get("score")
        r = score_module(module, verbose=False)
        if "error" in r:
            print(f"  FAIL  {module:18s} scoring error: {r['error']}")
            failures.append(module)
            continue
        cur = float(r["score"])
        reasons = []
        if old is not None and cur < old - args.allowed_drop:
            reasons.append(f"regressed {old:.1f}→{cur:.1f} (>{args.allowed_drop:.1f} drop)")
        if cur < args.floor:
            reasons.append(f"below floor {args.floor:.1f}")
        if reasons:
            print(f"  FAIL  {module:18s} {cur:5.1f}  ({'; '.join(reasons)})")
            failures.append(module)
        else:
            base = f"baseline {old:.1f}" if old is not None else "no baseline"
            print(f"  ok    {module:18s} {cur:5.1f}  ({base})")

    print()
    if failures:
        print(f"GATE FAILED — {len(failures)} module(s) regressed or below floor: "
              f"{', '.join(failures)}", file=sys.stderr)
        print("Run: python scripts/score_module.py <module> --verbose  to diagnose.",
              file=sys.stderr)
        sys.exit(1)

    print(f"GATE PASSED — all {len(baselines)} modules meet their forge baseline.")
    sys.exit(0)


if __name__ == "__main__":
    main()
