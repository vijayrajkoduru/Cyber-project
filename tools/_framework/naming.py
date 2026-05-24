"""VL-FOUNDRY — scanner naming convention validator.

Caught 6 duplicate scanners in the wild (cms vs cms_detection, jwt vs
jwt_scan, idor vs idor_detector, nosql vs nosqli, force_browse vs
forced_browsing, xss vs stored_xss). This module enforces canonical
naming + detects future duplicates at commit time.
"""
from __future__ import annotations
import re
from pathlib import Path

# ── Canonical naming rules ──────────────────────────────────────────────────

# Allowed scanner name pattern: lowercase + underscores + digits
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,40}$")

# Patterns that indicate duplication intent (banned suffixes)
_DUPLICATE_SUFFIXES = ("_detection", "_detector", "_scan", "_check",
                       "_test", "_v2", "_new", "_old", "_legacy", "_alt")

# Patterns that indicate plural-vs-singular sloppiness
_PLURAL_SINGULAR_PAIRS = [
    ("nosql", "nosqli"),
    ("force_browse", "forced_browsing"),
    ("xss", "stored_xss"),       # legitimate exception — both have a place
    ("sqli", "sql_injection"),
    ("idor", "idor_detector"),
    ("cms", "cms_detection"),
    ("jwt", "jwt_scan"),
]

# Allowed module names (extend when new module is forged)
_VALID_MODULES = {"recon", "vuln", "webapp", "osint", "password", "exploit",
                  "bof", "mobile", "api", "cloud", "network"}


def validate_scanner_name(name: str) -> tuple[bool, str]:
    """Return (is_valid, reason). Used by score_module.py + pre-commit hook."""
    if not _NAME_RE.match(name):
        return False, (f"Scanner name '{name}' must be lowercase alpha+digit+"
                       f"underscore, 3-40 chars, start with letter")
    for sfx in _DUPLICATE_SUFFIXES:
        if name.endswith(sfx):
            # Allow if no shorter version exists in the same module
            shorter = name[: -len(sfx)]
            if shorter:
                return False, (f"Scanner name '{name}' uses banned suffix "
                               f"'{sfx}'. Use '{shorter}' instead, or rename "
                               f"the existing '{shorter}' to clarify the diff.")
    return True, ""


def validate_module_name(name: str) -> tuple[bool, str]:
    """Module names must be in the allowed list."""
    if name not in _VALID_MODULES:
        return False, (f"Module '{name}' not in allowed set. Add to "
                       f"_VALID_MODULES in tools/_shared/naming.py first.")
    return True, ""


def detect_duplicates(scanner_names: list[str]) -> list[tuple[str, str, str]]:
    """Return list of (name_a, name_b, reason) for suspected duplicates.

    Used by CI / pre-commit hook to fail on accidental dupes.
    """
    dupes = []
    names_set = set(scanner_names)
    # Check banned plural/singular pairs
    for a, b in _PLURAL_SINGULAR_PAIRS:
        if a in names_set and b in names_set:
            # Some are legit (xss vs stored_xss). Allow allow-list:
            if (a, b) in (("xss", "stored_xss"),):
                continue
            dupes.append((a, b, f"Pluralization confusion — pick one"))

    # Check banned-suffix near-duplicates
    for n in scanner_names:
        for sfx in _DUPLICATE_SUFFIXES:
            if n.endswith(sfx):
                shorter = n[: -len(sfx)]
                if shorter in names_set:
                    dupes.append((n, shorter, f"'{n}' is a duplicate of '{shorter}' "
                                              f"via banned suffix '{sfx}'"))
    return dupes


def scan_module_for_violations(module: str) -> dict:
    """Walk tools/<module>/ and return violations report.

    Returns:
      {
        "module": str,
        "invalid_names": [(name, reason), ...],
        "duplicates": [(name_a, name_b, reason), ...],
        "violations_total": int,
      }
    """
    root = Path(__file__).resolve().parent.parent.parent / "tools" / module
    if not root.exists():
        return {"error": f"tools/{module}/ not found"}
    scanner_names = []
    for p in root.rglob("*.py"):
        if "__pycache__" in p.parts or "_legacy" in str(p):
            continue
        if p.name.startswith("_"):
            continue
        scanner_names.append(p.stem)
    invalid = []
    for n in scanner_names:
        ok, reason = validate_scanner_name(n)
        if not ok:
            invalid.append((n, reason))
    duplicates = detect_duplicates(scanner_names)
    return {
        "module": module,
        "invalid_names": invalid,
        "duplicates": duplicates,
        "violations_total": len(invalid) + len(duplicates),
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m tools._shared.naming <module>")
        sys.exit(2)
    report = scan_module_for_violations(sys.argv[1])
    print(f"\nNaming-convention report for {sys.argv[1]}:")
    print(f"  Invalid names:  {len(report.get('invalid_names', []))}")
    for n, r in report.get("invalid_names", []):
        print(f"    - {n}: {r}")
    print(f"  Duplicates:     {len(report.get('duplicates', []))}")
    for a, b, r in report.get("duplicates", []):
        print(f"    - {a} <-> {b}: {r}")
    if report.get("violations_total", 0) > 0:
        sys.exit(1)
    print(f"\n  All names valid, no duplicates. ✓")
