#!/usr/bin/env python3
"""Splits tools/recon/recon_module.py into one isolated file per endpoint."""
import ast
import shutil
import sys
import py_compile
import tempfile
from pathlib import Path

RECON_DIR = Path("tools/recon")
SRC = RECON_DIR / "recon_module.py"
BACKUP = RECON_DIR / "recon_module.py.bak"

EXISTING_FILES = {
    "cve_match.py", "dns.py", "portscan.py",
    "ssl_cert.py", "techstack.py", "_helpers.py",
    "__init__.py", "recon_module.py", "recon_module.py.bak",
}
ENDPOINT_FILE_OVERRIDES = {"/api/recon/dns": "recon_dns.py"}


def parse_module(src_text):
    tree = ast.parse(src_text)
    raw_lines = src_text.splitlines(keepends=True)

    def src_of(node):
        if hasattr(node, "decorator_list") and node.decorator_list:
            start = min(d.lineno for d in node.decorator_list) - 1
        else:
            start = node.lineno - 1
        return "".join(raw_lines[start:node.end_lineno])

    def start_with_decorators(node):
        if hasattr(node, "decorator_list") and node.decorator_list:
            return min(d.lineno for d in node.decorator_list)
        return node.lineno

    endpoints, helpers, import_lines = [], {}, []

    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            import_lines.append(src_of(node).rstrip())
            continue
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id.startswith("_"):
                    helpers[tgt.id] = {"kind": "const", "src": src_of(node),
                                       "start_line": node.lineno, "end_line": node.end_lineno}
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            is_endpoint, route = False, None
            for dec in node.decorator_list:
                if (isinstance(dec, ast.Call)
                        and isinstance(dec.func, ast.Attribute)
                        and dec.func.attr in ("post", "get")
                        and isinstance(dec.func.value, ast.Name)
                        and dec.func.value.id == "router"):
                    is_endpoint = True
                    if dec.args and isinstance(dec.args[0], ast.Constant):
                        route = dec.args[0].value
                    break
            if is_endpoint:
                needs = {n.id for n in ast.walk(node)
                         if isinstance(n, ast.Name) and n.id.startswith("_")}
                endpoints.append({"route": route, "name": node.name,
                                  "src": src_of(node), "needs_helpers": needs,
                                  "start_line": start_with_decorators(node),
                                  "end_line": node.end_lineno})
            elif node.name.startswith("_"):
                helpers[node.name] = {"kind": "func", "src": src_of(node),
                                      "start_line": start_with_decorators(node),
                                      "end_line": node.end_lineno}
    return endpoints, helpers, import_lines


def transitive_helpers(start, helpers, seen=None):
    if seen is None: seen = set()
    if start not in helpers or start in seen: return seen
    seen.add(start)
    if helpers[start]["kind"] == "func":
        try:
            tree = ast.parse(helpers[start]["src"])
        except SyntaxError:
            return seen
        for inner in ast.walk(tree):
            if isinstance(inner, ast.Name) and inner.id.startswith("_"):
                transitive_helpers(inner.id, helpers, seen)
    return seen


def generate_tool_file(endpoint, helpers, all_imports):
    needed = set()
    for h in endpoint["needs_helpers"]:
        transitive_helpers(h, helpers, needed)
    needed = {n for n in needed if n in helpers}
    consts = sorted([n for n in needed if helpers[n]["kind"] == "const"])
    funcs  = sorted([n for n in needed if helpers[n]["kind"] == "func"])

    parts = [
        f'"""{endpoint["name"]} -- isolated tool (Kali-style architecture).',
        "",
        f"Route: {endpoint['route']}",
        "Split from recon_module.py monolith by scripts/split_recon_module.py.",
        "Failure here is quarantined by the healing autoloader -- other tools unaffected.",
        '"""',
        "",
    ]
    parts.extend(all_imports)
    parts.extend(["", "from fastapi import APIRouter, Depends", "", "router = APIRouter()", ""])
    for h in consts:
        parts.append(helpers[h]["src"].rstrip()); parts.append("")
    for h in funcs:
        parts.append(helpers[h]["src"].rstrip()); parts.append("")
    parts.append(endpoint["src"].rstrip())
    parts.extend(["", "", "def register(app):", "    app.include_router(router)", ""])
    return "\n".join(parts)


def remove_lines(src_text, ranges):
    lines = src_text.splitlines(keepends=True)
    drop = set()
    for s, e in ranges:
        for i in range(s - 1, e): drop.add(i)
    return "".join(l for i, l in enumerate(lines) if i not in drop)


def main():
    if not SRC.exists():
        print(f"ERROR: {SRC} not found")
        return 1
    src_text = SRC.read_text(encoding="utf-8")
    shutil.copy(SRC, BACKUP)
    print(f"[backup] {BACKUP}")

    endpoints, helpers, imports = parse_module(src_text)
    print(f"[parse] {len(endpoints)} endpoints, {len(helpers)} helpers\n")

    extracted, skipped, generated_files = [], [], []

    for ep in endpoints:
        if not ep["route"]:
            skipped.append((ep["name"], "no route")); continue
        route_name = ep["route"].rsplit("/", 1)[-1]
        filename = ENDPOINT_FILE_OVERRIDES.get(ep["route"], f"{route_name}.py")
        if filename in EXISTING_FILES:
            skipped.append((ep["name"], f"collides with {filename}")); continue
        target = RECON_DIR / filename
        content = generate_tool_file(ep, helpers, imports)
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False,
                                          dir=RECON_DIR, encoding="utf-8")
        tmp.write(content); tmp.close()
        tmp_path = Path(tmp.name)
        try:
            py_compile.compile(str(tmp_path), doraise=True)
        except py_compile.PyCompileError as exc:
            tmp_path.unlink()
            skipped.append((ep["name"], f"py_compile failed: {str(exc)[:80]}"))
            continue
        tmp_path.replace(target)
        extracted.append(ep); generated_files.append(target)
        print(f"  + {target.name:40} {len(content.splitlines()):>4} lines  {ep['route']}")

    print(f"\n[extract] {len(extracted)}/{len(endpoints)} succeeded")
    if skipped:
        print(f"[skip] {len(skipped)} stayed in recon_module.py:")
        for n, r in skipped: print(f"  - {n}: {r}")

    if not extracted:
        return 0

    line_ranges = [(ep["start_line"], ep["end_line"]) for ep in extracted]
    new_src = remove_lines(src_text, line_ranges)
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False,
                                      dir=RECON_DIR, encoding="utf-8")
    tmp.write(new_src); tmp.close()
    tmp_path = Path(tmp.name)
    try:
        py_compile.compile(str(tmp_path), doraise=True)
    except py_compile.PyCompileError as exc:
        tmp_path.unlink()
        print(f"\n[ROLLBACK] shrunk recon_module.py won't parse: {exc}")
        for f in generated_files: f.unlink()
        shutil.copy(BACKUP, SRC)
        return 2
    tmp_path.replace(SRC)
    old, new = len(src_text.splitlines()), len(new_src.splitlines())
    print(f"\n[recon_module.py] shrunk: {old} -> {new} lines (-{old - new})")
    print("\nDONE.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
