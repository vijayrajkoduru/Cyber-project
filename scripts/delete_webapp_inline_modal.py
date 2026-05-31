"""Remove the now-wrapped inline PDFConfigModal duplicate from src/App.js.

We left a `{false && showPDFModal && (` marker right before the old inline
modal block. This script finds that marker and deletes everything up to
its matching `)}` (balanced parentheses + braces).
"""
from pathlib import Path

APP = Path("src/App.js")
src = APP.read_text(encoding="utf-8")

MARKER = "{false && showPDFModal && ("
i = src.find(MARKER)
if i == -1:
    print("Marker not found — nothing to do.")
    raise SystemExit(0)

# Walk forward tracking { ( depth — depth starts at 1 for the outer `{`.
n = len(src)
depth = 1   # the `{` of `{false && ...}`
j = i + 1   # position of `false`
in_str = None
while j < n and depth > 0:
    c = src[j]
    if in_str:
        if c == "\\": j += 2; continue
        if c == in_str: in_str = None
        j += 1; continue
    if c in ("'", '"', "`"):
        in_str = c; j += 1; continue
    if c == "/" and j+1 < n and src[j+1] == "/":
        j = src.find("\n", j); j = j+1 if j != -1 else n; continue
    if c == "/" and j+1 < n and src[j+1] == "*":
        e = src.find("*/", j+2); j = e+2 if e != -1 else n; continue
    if c == "{": depth += 1
    elif c == "}": depth -= 1
    j += 1

end = j  # one past the closing `}`
# Swallow trailing newline(s) for tidiness.
while end < n and src[end] == "\n":
    end += 1

removed = src[i:end]
line_count = removed.count("\n")
print(f"Removing dead inline-modal block: {line_count} lines (offsets {i}-{end}).")
src = src[:i] + src[end:]

APP.write_text(src, encoding="utf-8")
print("Done.")
