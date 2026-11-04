#!/usr/bin/env python3
"""
check_undefined.py — dependency-free guard against the bug class that
500'd /api/scan/login: a name that is CALLED but defined nowhere
(e.g. _resolve_underscore). Pure stdlib, so it runs anywhere with no
ruff/pyflakes install.

For every function in the scanned tree it builds a conservative set of
"known" names = builtins + module-level bindings + every name bound
anywhere inside the function (params, assignments, walrus, for/with/except
targets, comprehension targets, imports, global/nonlocal, nested def/class
names). Any Name used in Load context that is NOT in that set is reported
as undefined. Conservative by design: it over-approximates bindings so it
never false-positives on valid code, but a name bound NOWHERE (the real
bug) is always caught.

Exit 0 = clean, 1 = undefined names found, 2 = a file failed to parse.
"""
import ast
import builtins
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# What to scan: the app's own Python. Skip vendored / archived / test trees.
SCAN_DIRS = ["tools", "endpoints", "agents"]
SCAN_FILES = ["main.py"]
SKIP_PARTS = {"_archive", "node_modules", ".snapshots", "__pycache__",
              "last_known_good", "backups"}

BUILTINS = set(dir(builtins)) | {
    "__file__", "__name__", "__doc__", "__package__", "__loader__",
    "__spec__", "__builtins__", "__annotations__", "__dict__", "__class__",
}


def _bound_names_in(node):
    """Every name bound anywhere in this subtree (over-approximation)."""
    bound = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store,)):
            bound.add(n.id)
        elif isinstance(n, ast.arg):
            bound.add(n.arg)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(n.name)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            bound.add(n.name)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for a in n.names:
                bound.add((a.asname or a.name).split(".")[0])
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            bound.update(n.names)
        elif isinstance(n, ast.NamedExpr) and isinstance(n.target, ast.Name):
            bound.add(n.target.id)
    return bound


def _module_globals(tree):
    g = set(BUILTINS)
    g |= _bound_names_in(tree)  # module-level over-approximation
    return g


def check_file(path):
    src = path.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError as e:
        return [("SYNTAX", e.lineno or 0, f"{e.msg}")], True

    g = _module_globals(tree)
    findings = []

    # Each function: known = globals + everything bound in its own subtree.
    # Collect Load names and flag those unknown. Attribute access (x.y) only
    # checks the root (x), never the attribute, so missing methods are ignored.
    def visit_fn(fn):
        known = set(g) | _bound_names_in(fn)
        for n in ast.walk(fn):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                if n.id not in known:
                    findings.append(("UNDEFINED", n.lineno,
                                     f"{n.id!r} in {fn.name}()"))

    seen = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if id(n) not in seen:
                seen.add(id(n))
                visit_fn(n)

    # Module-level Load names (outside any function).
    fn_nodes = [n for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    fn_name_ids = set()
    for f in fn_nodes:
        for sub in ast.walk(f):
            fn_name_ids.add(id(sub))
    for n in ast.walk(tree):
        if (isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
                and id(n) not in fn_name_ids and n.id not in g):
            findings.append(("UNDEFINED", n.lineno, f"{n.id!r} at module level"))

    return findings, False


def iter_targets(explicit):
    if explicit:
        for p in explicit:
            yield Path(p)
        return
    for d in SCAN_DIRS:
        base = ROOT / d
        if not base.exists():
            continue
        for p in base.rglob("*.py"):
            if SKIP_PARTS & set(p.parts):
                continue
            yield p
    for f in SCAN_FILES:
        p = ROOT / f
        if p.exists():
            yield p


def main(argv):
    explicit = [a for a in argv if not a.startswith("-")]
    total = 0
    parse_fail = False
    for path in iter_targets(explicit):
        findings, failed = check_file(path)
        parse_fail = parse_fail or failed
        for kind, line, msg in findings:
            rel = path.relative_to(ROOT) if ROOT in path.resolve().parents or path.resolve() == ROOT else path
            print(f"{kind}: {rel}:{line}: {msg}")
            total += 1
    if parse_fail:
        print("\nFAIL: one or more files did not parse.")
        return 2
    if total:
        print(f"\nFAIL: {total} undefined-name reference(s) found.")
        return 1
    print("OK: no undefined-name references.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
