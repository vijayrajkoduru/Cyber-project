#!/usr/bin/env python3
"""VL-FOUNDRY Layer 21 — Tool & dependency freshness checker.

Five health checks:
  1. Python deps installed (every line in requirements.txt resolves)
  2. Python deps current (pip list --outdated vs pinned)
  3. External CLI tools on PATH (which nmap / nuclei / ...)
  4. External CLI tools meet minimum version
  5. Wordlist freshness (mtime vs Layer 5 refresh calendar)

Reports only by default. Use --install / --update to remediate.

Usage:
  python scripts/doctor.py              # check only
  python scripts/doctor.py --install    # pip install missing
  python scripts/doctor.py --update     # pip install -U outdated
  python scripts/doctor.py --json       # machine-readable

Exit codes:
  0 — all green
  1 — something REQUIRED is missing (blocks CI)
  2 — something is outdated (warning only)
"""
from __future__ import annotations
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

REQ_FILE = ROOT / "requirements.txt"
TOOLS_FILE = ROOT / "tools" / "_framework" / "tool_versions.json"
PAYLOADS_DIR = ROOT / "tools" / "_payloads"


# ─────────── Python deps ───────────

def parse_requirements() -> list[tuple[str, str | None]]:
    """Return [(pkg, pinned_version_or_None), ...]."""
    if not REQ_FILE.exists():
        return []
    out = []
    for raw in REQ_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*(?:==|>=)?\s*([^\s;]+)?", line)
        if m:
            out.append((m.group(1).lower().split("[")[0], m.group(2)))
    return out


def python_dep_health() -> dict:
    """Check every package in requirements.txt is importable."""
    deps = parse_requirements()
    if not deps:
        return {"status": "skip", "reason": "no requirements.txt"}

    missing, ok = [], []
    try:
        import importlib.metadata as md
        installed = {d.metadata["Name"].lower(): d.version
                     for d in md.distributions() if d.metadata.get("Name")}
    except Exception as e:
        return {"status": "error", "reason": str(e)}

    for pkg, pin in deps:
        if pkg in installed:
            ok.append((pkg, installed[pkg], pin))
        else:
            missing.append((pkg, pin))

    # Outdated check is best-effort: only flag those with hard pins where
    # the installed version differs from the pin.
    outdated = [(p, installed[p], pin)
                for p, pin in deps
                if pin and p in installed and installed[p] != pin]

    return {
        "status": "ok" if not missing else "fail",
        "installed": len(ok),
        "missing": missing,
        "outdated": outdated,
    }


def pip_install(packages: list[str], upgrade: bool = False) -> bool:
    cmd = [sys.executable, "-m", "pip", "install"]
    if upgrade:
        cmd.append("-U")
    cmd.extend(packages)
    print(f"  $ {' '.join(cmd)}")
    return subprocess.call(cmd) == 0


# ─────────── External CLI tools ───────────

def load_tool_manifest() -> dict:
    if not TOOLS_FILE.exists():
        return {"tools": [], "wordlist_refresh_days": {}}
    return json.loads(TOOLS_FILE.read_text(encoding="utf-8"))


def _version_tuple(v: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts[:4])


def cli_tool_health(manifest: dict) -> dict:
    results = []
    missing_required = []
    for tool in manifest.get("tools", []):
        name = tool["name"]
        on_path = shutil.which(name)
        if not on_path:
            results.append({"name": name, "status": "MISSING",
                            "required": tool.get("required", False)})
            if tool.get("required"):
                missing_required.append(name)
            continue
        # Probe version
        try:
            proc = subprocess.run(
                tool["check_cmd"], capture_output=True, text=True, timeout=8
            )
            blob = (proc.stdout or "") + (proc.stderr or "")
            m = re.search(tool["parse_re"], blob)
            found = m.group(1) if m else "?"
            cur = _version_tuple(found) if found != "?" else ()
            minv = _version_tuple(tool["min_version"])
            ok = bool(cur) and cur >= minv
            results.append({
                "name": name,
                "status": "OK" if ok else "OUTDATED",
                "found": found,
                "min": tool["min_version"],
                "path": on_path,
            })
        except Exception as e:
            results.append({"name": name, "status": "ERROR", "error": str(e)})
    status = "fail" if missing_required else (
        "warn" if any(r["status"] in ("OUTDATED", "MISSING") for r in results)
        else "ok"
    )
    return {"status": status, "tools": results}


# ─────────── Wordlist freshness ───────────

def wordlist_health(manifest: dict) -> dict:
    """Check mtime of AI-curated wordlists vs refresh calendar."""
    if not PAYLOADS_DIR.exists():
        return {"status": "skip", "reason": "no tools/_payloads/"}
    cal = manifest.get("wordlist_refresh_days", {})
    now = time.time()
    stale = []
    fresh = 0
    for mod_dir in PAYLOADS_DIR.iterdir():
        if not mod_dir.is_dir():
            continue
        mod = mod_dir.name
        max_days = cal.get(mod, 30)
        for f in mod_dir.glob("*.py"):
            if f.name.startswith("_"):
                continue
            age_days = (now - f.stat().st_mtime) / 86400
            if age_days > max_days:
                stale.append({"file": str(f.relative_to(ROOT)),
                              "age_days": round(age_days, 1),
                              "max_days": max_days})
            else:
                fresh += 1
    return {
        "status": "warn" if stale else "ok",
        "fresh_count": fresh,
        "stale": stale,
    }


# ─────────── Reporting ───────────

def render_text(report: dict) -> int:
    print("═" * 65)
    print("  VL-FOUNDRY Layer 21 — doctor.py")
    print("═" * 65)

    # Python deps
    py = report["python"]
    print(f"\n  Python deps:")
    if py["status"] == "skip":
        print(f"    -- skipped ({py['reason']})")
    else:
        print(f"    ✓ installed: {py['installed']}")
        if py["missing"]:
            for pkg, pin in py["missing"]:
                pin_s = f"=={pin}" if pin else ""
                print(f"    ✗ MISSING: {pkg}{pin_s}")
        if py["outdated"]:
            for pkg, cur, pin in py["outdated"]:
                print(f"    ⚠ OUTDATED: {pkg} installed={cur} pinned={pin}")

    # CLI tools
    cli = report["cli"]
    print(f"\n  External CLI tools:")
    for t in cli["tools"]:
        if t["status"] == "OK":
            print(f"    ✓ {t['name']:12s} {t.get('found','?'):>10s}  {t.get('path','')}")
        elif t["status"] == "OUTDATED":
            print(f"    ⚠ {t['name']:12s} {t.get('found','?'):>10s}  "
                  f"(need >= {t.get('min','?')})")
        elif t["status"] == "MISSING":
            req = "REQUIRED" if t.get("required") else "optional"
            mark = "✗" if t.get("required") else "·"
            print(f"    {mark} {t['name']:12s} {'not on PATH':>15s}  ({req})")
        else:
            print(f"    ! {t['name']:12s} {t.get('error', 'probe failed')}")

    # Wordlists
    wl = report["wordlists"]
    print(f"\n  Wordlist freshness:")
    if wl["status"] == "skip":
        print(f"    -- skipped ({wl['reason']})")
    else:
        print(f"    ✓ fresh: {wl['fresh_count']}")
        for s in wl["stale"]:
            print(f"    ⚠ STALE: {s['file']}  "
                  f"age={s['age_days']}d > {s['max_days']}d")

    # Verdict
    print(f"\n{'─' * 65}")
    if report["exit"] == 0:
        print("  ✅ ALL GREEN")
    elif report["exit"] == 2:
        print("  ⚠️  WARNINGS (outdated/stale — not blocking)")
    else:
        print("  ❌ FAILURES (missing required deps/tools)")
    print("═" * 65)
    return report["exit"]


def build_report(manifest: dict) -> dict:
    py = python_dep_health()
    cli = cli_tool_health(manifest)
    wl = wordlist_health(manifest)

    # Determine exit code: 1 if anything REQUIRED is missing, 2 if warnings only
    exit_code = 0
    if py.get("status") == "fail" or cli.get("status") == "fail":
        exit_code = 1
    elif any(x.get("status") == "warn" for x in (cli, wl)) or py.get("outdated"):
        exit_code = 2

    return {"python": py, "cli": cli, "wordlists": wl, "exit": exit_code}


def main():
    ap = argparse.ArgumentParser(
        description="VL-FOUNDRY Layer 21 — deps + tools + wordlist freshness"
    )
    ap.add_argument("--install", action="store_true",
                    help="pip-install missing Python deps")
    ap.add_argument("--update", action="store_true",
                    help="pip install -U outdated Python deps")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable JSON output")
    args = ap.parse_args()

    manifest = load_tool_manifest()
    report = build_report(manifest)

    # Remediation
    if args.install and report["python"].get("missing"):
        pkgs = [f"{p}=={v}" if v else p
                for p, v in report["python"]["missing"]]
        if pip_install(pkgs, upgrade=False):
            print("  ✓ install OK — re-running check")
            report = build_report(manifest)
    if args.update and report["python"].get("outdated"):
        pkgs = [p for p, _, _ in report["python"]["outdated"]]
        if pip_install(pkgs, upgrade=True):
            print("  ✓ update OK — re-running check")
            report = build_report(manifest)

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        render_text(report)

    sys.exit(report["exit"])


if __name__ == "__main__":
    main()
