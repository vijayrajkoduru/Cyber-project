"""One-shot dead-code deletion for src/App.js.

Removes:
  - function ZAPModule(...) { ... }
  - function <Name>Module_legacy(...) { ... }   (12+ of them)

Walks balanced parentheses to skip past the parameter list, THEN starts
brace tracking from the function-body `{`. Treats string literals and
comments correctly so a `{` inside them doesn't fool the depth counter.

Run from repo root:  python3 scripts/delete_dead_code.py
"""
from pathlib import Path
import re

APP = Path("src/App.js")
src = APP.read_text(encoding="utf-8")

DEAD_FN_RE = re.compile(
    r"^function\s+(?:ZAPModule|[A-Za-z]+_legacy)\s*\(",
    re.MULTILINE,
)

def skip_string(text: str, i: int) -> int:
    """text[i] is the opening quote. Returns index past the closing quote."""
    quote = text[i]; i += 1; n = len(text)
    while i < n:
        c = text[i]
        if c == "\\": i += 2; continue
        if c == quote: return i + 1
        i += 1
    return i

def skip_comment_or_string(text: str, i: int) -> int | None:
    """If text[i:] is a comment or string literal start, skip past it.
    Returns new index, or None if there's no comment/string at i."""
    if i + 1 < len(text) and text[i] == "/" and text[i+1] == "/":
        nl = text.find("\n", i)
        return (nl + 1) if nl != -1 else len(text)
    if i + 1 < len(text) and text[i] == "/" and text[i+1] == "*":
        end = text.find("*/", i + 2)
        return (end + 2) if end != -1 else len(text)
    if text[i] in ("'", '"', "`"):
        return skip_string(text, i)
    return None

def skip_balanced(text: str, i: int, open_ch: str, close_ch: str) -> int:
    """text[i] == open_ch. Returns index past the matching close_ch,
    skipping comments and strings."""
    assert text[i] == open_ch
    depth = 1; i += 1; n = len(text)
    while i < n and depth > 0:
        j = skip_comment_or_string(text, i)
        if j is not None: i = j; continue
        c = text[i]
        if c == open_ch: depth += 1
        elif c == close_ch: depth -= 1
        i += 1
    return i

def find_fn_body_end(text: str, fn_start: int) -> int:
    """fn_start points at `function`. Skip past the parameter list, then
    the function body, and return the index after the body's closing `}`.
    """
    # Find the opening `(` of the parameter list.
    paren = text.index("(", fn_start)
    # Skip past the balanced `(...)` — this consumes destructuring `{...}`
    # inside the parameter list correctly.
    after_paren = skip_balanced(text, paren, "(", ")")
    # Skip whitespace until the body `{`.
    while after_paren < len(text) and text[after_paren] in " \t\r\n":
        after_paren += 1
    if after_paren >= len(text) or text[after_paren] != "{":
        raise ValueError(f"No function body `{{` found after params at offset {fn_start}")
    return skip_balanced(text, after_paren, "{", "}")

removed = []
matches = list(DEAD_FN_RE.finditer(src))
print(f"Found {len(matches)} dead function definitions.")

for m in reversed(matches):
    fn_start = m.start()
    fn_end = find_fn_body_end(src, fn_start)
    while fn_end < len(src) and src[fn_end] == "\n":
        fn_end += 1
    block = src[fn_start:fn_end]
    name = re.match(r"function\s+(\w+)", block).group(1)
    line_no = src[:fn_start].count("\n") + 1
    line_count = block.count("\n")
    removed.append((name, line_no, line_count))
    # Collapse to a single blank line so neighbouring sections stay separated.
    src = src[:fn_start] + "\n" + src[fn_end:]

# Drop the dead useState setter (customWordlist is read but never set).
src2, n_setter = re.subn(
    r"const\s+\[customWordlist,\s*setCustomWordlist\]\s*=\s*useState\(null\);\s*\n",
    "  const customWordlist = null; // VL-CLEANUP: setter was dead; collapsed to const\n",
    src,
)
if n_setter:
    print(f"Collapsed dead setCustomWordlist useState ({n_setter} occurrence).")
    src = src2

# Drop the stale BUG-FIX comment trio (3 consecutive comment lines).
src3, n_comment = re.subn(
    r"\s*// BUG-FIX 2026-05-22: previously checked dead _pci/_soc/_iso maps[^\n]*\n[ \t]*//[^\n]*\n[ \t]*//[^\n]*\n",
    "\n",
    src,
)
if n_comment:
    print(f"Dropped stale BUG-FIX comment block ({n_comment} occurrence).")
    src = src3

APP.write_text(src, encoding="utf-8")

print("\n=== REMOVED ===")
for name, ln, lc in sorted(removed, key=lambda x: x[1]):
    print(f"  L{ln:>5} - {name:35s} ({lc} lines)")
print(f"\nTotal: {sum(lc for _,_,lc in removed)} lines from {len(removed)} dead functions.")
