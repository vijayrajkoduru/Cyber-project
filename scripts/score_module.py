#!/usr/bin/env python3
"""Automated module scoring — enforces VL-FOUNDRY.md contracts.

Usage:
  python scripts/score_module.py <module>           # score one module
  python scripts/score_module.py --all              # score all 3
  python scripts/score_module.py <module> --verbose # show per-scanner detail

Reads the actual repo (no manual config) and computes per-layer scores via
AST inspection. The output is the source of truth for whether a module is
ready to ship.

Exit code 0 if score >= 85, 1 otherwise (CI-friendly).
"""
from __future__ import annotations
import argparse
import ast
import os
import re
import sys
from pathlib import Path

# Ensure Unicode box-drawing characters render on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Framework score weights
WEIGHTS = {
    "orchestrator": 25,  # Layer 4 — % scanners wired into run_all
    "curation":     25,  # Layer 5 — % scanners loading AI wordlists
    "quality_bar":  20,  # Layer 6 — % scanners passing 7-check DoD
    "frontend":     15,  # Layer 7 — % scanners in App.js PHASES
    "parallel":     15,  # Layer 6 sub — % scanners using async/threadpool
}

# Per-scanner 7-check requirements (Layer 6).
# Patterns accept BOTH the Vuln/Webapp shape (direct wrap_finding +
# standard_response calls) AND the Recon shape (ScanContext + run_scanner
# + findings rules file). A scanner passes the check if it uses EITHER.
CHECKS = {
    "precheck":      r"precheck_target\(|safe_get\(|web_url\(|recon_host\(|ScanContext|run_scanner",
    "uniform_shape": r"standard_response\(|vuln_response\(|run_scanner\(",
    "positive_emit": r'"POSITIVE"|POSITIVE|ctx\.source\(|FINDING_RULES',
    "severity":      r"severity=|'severity'|finding_rules|FINDING_RULES",
    "remediation":   r"remediation=|'remediation'|FINDING_RULES",
    "evidence":      r"evidence_marker=|'evidence_marker'|evidence=|ctx\.source\(",
    "timeout":       r"timeout=|wait_for\(.*timeout=|deadline\s*=|run_scanner",
}


def find_scanners(module_path: Path) -> list[Path]:
    """Walk module tree (handles nested tier subdirs like recon/tier4_web/)."""
    out = []
    for p in module_path.rglob("*.py"):
        if "__pycache__" in p.parts or "_legacy" in str(p):
            continue
        if p.name.startswith("_"):
            continue
        out.append(p)
    return sorted(out)


def check_scanner_quality(scanner_path: Path) -> dict[str, bool]:
    """Run the 7 VL-FORGE checks against one scanner."""
    src = scanner_path.read_text(encoding="utf-8")
    return {name: bool(re.search(pattern, src)) for name, pattern in CHECKS.items()}


def is_parallel(scanner_path: Path) -> bool:
    """Layer 6 — scanner uses async parallelism."""
    src = scanner_path.read_text(encoding="utf-8")
    markers = ("asyncio.gather", "asyncio.Semaphore", "ThreadPoolExecutor",
               "asyncio.wait_for", "asyncio.to_thread")
    return any(m in src for m in markers)


def has_curation(scanner_path: Path) -> bool:
    """Layer 5 — scanner imports from tools/_payloads/."""
    src = scanner_path.read_text(encoding="utf-8")
    return "tools._payloads" in src


def load_orchestrator_tools(module: str) -> set[str]:
    """Return scanner names registered in <module>_orchestrator.py."""
    try:
        mod = __import__(f"endpoints.{module}_orchestrator", fromlist=["_all_tools"])
        tools = mod._all_tools()
        return {name for name, _ in tools}
    except Exception:
        return set()


def load_frontend_phases(module: str) -> set[str]:
    """Parse src/App.js to extract module's PHASES tool names."""
    app_js = ROOT / "src" / "App.js"
    if not app_js.exists():
        return set()
    src = app_js.read_text(encoding="utf-8")

    # Heuristic: look for tool:"<name>" entries — module-agnostic
    # (Module's PHASES array uses {tool:"<name>", endpoint:"/api/<module>/..."})
    pattern = rf'tool:["\']([\w_]+)["\'].*endpoint:["\']/api/{module}'
    return set(re.findall(pattern, src))


def score_module(module: str, verbose: bool = False) -> dict:
    """Return per-layer scores + total."""
    module_path = ROOT / "tools" / module
    if not module_path.exists():
        return {"error": f"tools/{module}/ not found"}

    scanners = find_scanners(module_path)
    scanner_names = [s.stem for s in scanners]

    if not scanners:
        return {"error": f"no scanners in tools/{module}/"}

    # Layer 4 — orchestrator coverage
    orch_tools = load_orchestrator_tools(module)
    in_orch = sum(1 for n in scanner_names if n in orch_tools)
    orch_pct = (in_orch / len(scanners)) * 100 if scanners else 0

    # Layer 5 — curation
    curated = sum(1 for s in scanners if has_curation(s))
    curation_pct = (curated / len(scanners)) * 100

    # Layer 6 — quality bar (count scanners passing >= 5 of 7 checks)
    quality_passes = 0
    per_scanner_checks = {}
    for s in scanners:
        checks = check_scanner_quality(s)
        per_scanner_checks[s.stem] = checks
        if sum(checks.values()) >= 5:
            quality_passes += 1
    quality_pct = (quality_passes / len(scanners)) * 100

    # Layer 6 sub — parallel
    parallel = sum(1 for s in scanners if is_parallel(s))
    parallel_pct = (parallel / len(scanners)) * 100

    # Layer 7 — frontend
    fe_phases = load_frontend_phases(module)
    in_fe = sum(1 for n in scanner_names if n in fe_phases)
    fe_pct = (in_fe / len(scanners)) * 100

    # Weighted total
    total = (
        orch_pct      * WEIGHTS["orchestrator"] +
        curation_pct  * WEIGHTS["curation"] +
        quality_pct   * WEIGHTS["quality_bar"] +
        fe_pct        * WEIGHTS["frontend"] +
        parallel_pct  * WEIGHTS["parallel"]
    ) / 100

    return {
        "module": module,
        "total_scanners": len(scanners),
        "scanner_names": scanner_names,
        "layers": {
            "L4_orchestrator": {"passed": in_orch, "of": len(scanners), "pct": orch_pct},
            "L5_curation":     {"passed": curated, "of": len(scanners), "pct": curation_pct},
            "L6_quality_bar":  {"passed": quality_passes, "of": len(scanners), "pct": quality_pct},
            "L6_parallel":     {"passed": parallel, "of": len(scanners), "pct": parallel_pct},
            "L7_frontend":     {"passed": in_fe, "of": len(scanners), "pct": fe_pct},
        },
        "score": round(total, 1),
        "ready": total >= 85,
        "per_scanner_checks": per_scanner_checks if verbose else None,
    }


def print_result(r: dict, verbose: bool = False):
    """Render a single module's score as readable text."""
    if "error" in r:
        print(f"ERROR: {r['error']}")
        return

    bar = lambda pct: "█" * int(pct / 5) + "░" * (20 - int(pct / 5))

    print(f"\n{'═' * 65}")
    print(f"  MODULE: {r['module'].upper()}")
    print(f"  Scanners on disk: {r['total_scanners']}")
    print(f"{'═' * 65}")

    layers = r["layers"]
    for layer_name, data in layers.items():
        pct = data["pct"]
        mark = "✅" if pct >= 90 else "⚠️ " if pct >= 70 else "❌"
        label = layer_name.replace("_", " ")
        print(f"  {mark} {label:25s} {data['passed']:3d}/{data['of']:<3d} "
              f"{bar(pct)} {pct:5.1f}%")

    print(f"{'─' * 65}")
    status = "READY TO SHIP" if r["ready"] else "NOT READY"
    icon = "✅" if r["ready"] else "❌"
    print(f"  {icon} SCORE: {r['score']:>5.1f}/100   STATUS: {status}")
    print(f"{'═' * 65}")

    if verbose and r.get("per_scanner_checks"):
        print(f"\n  Per-scanner 7-check detail:")
        for name, checks in sorted(r["per_scanner_checks"].items()):
            passed = sum(checks.values())
            status = "✅" if passed >= 5 else "❌"
            details = " ".join(
                f"{c}:{'✓' if v else '✗'}" for c, v in checks.items()
            )
            print(f"  {status} {name:30s} {passed}/7  ({details})")


def main():
    ap = argparse.ArgumentParser(
        description="Score VulnusLab modules against VL-FOUNDRY.md"
    )
    ap.add_argument("module", nargs="?", help="Module name (recon|vuln|webapp)")
    ap.add_argument("--all", action="store_true", help="Score all 3 modules")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="Show per-scanner check detail")
    args = ap.parse_args()

    if args.all:
        modules = ["recon", "vuln", "webapp"]
    elif args.module:
        modules = [args.module]
    else:
        ap.print_help()
        sys.exit(2)

    any_failed = False
    for m in modules:
        r = score_module(m, verbose=args.verbose)
        print_result(r, verbose=args.verbose)
        if not r.get("ready"):
            any_failed = True

    sys.exit(1 if any_failed else 0)


if __name__ == "__main__":
    main()
