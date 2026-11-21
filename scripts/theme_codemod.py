#!/usr/bin/env python3
"""ENTERPRISE-UI theme codemod.

Rewrites hard-coded neutral slate colours to CSS theme variables, ONLY inside:
  * JSX inline style objects     style={{ ... }}
  * DOM style assignments        el.style.prop = "..."
Global CSS is handled by hand (APP_CSS in App.js).

Accent text colours (#60a5fa, #4ade80, ...) are rewritten only when they are
the value of a `color` property, to var(--t-xxxxxx, #xxxxxx) so dark mode keeps
the exact original colour and light mode gets a darker, readable variant.

Never touches:
  * a colour that is concatenated with an alpha suffix ("#1e293b"+"22", `${c}33`)
    or that is already 8-digit hex (#1e293b80)
  * anything outside style objects (jsPDF / canvas / SVG attrs / data tables)
  * excluded line ranges (logged-out LandingPage / AuthLanding / Login / Tagline)

Usage: theme_codemod.py FILE [--exclude START-END ...] [--dry]
"""
import re
import sys

NEUTRAL = {
    "#020617": "var(--bg)",
    "#0a0f1e": "var(--surface)", "#0f172a": "var(--surface)",
    "#0a1628": "var(--surface2)", "#0a1224": "var(--surface2)", "#0b1324": "var(--surface2)",
    "#1e293b": "var(--border)",
    "#334155": "var(--border2)",
    "#475569": "var(--dim)", "#64748b": "var(--dim)",
    "#94a3b8": "var(--muted)",
    "#cbd5e1": "var(--text)", "#e2e8f0": "var(--text)",
    "#f1f5f9": "var(--heading)", "#f8fafc": "var(--heading)",
    "#1e3a8a": "var(--nav-active)",
}
# accent text colours that get a darker variant in light mode (see APP_CSS --t-*)
ACCENT_TEXT = ["#60a5fa", "#93c5fd", "#3b82f6", "#4ade80", "#86efac", "#22c55e",
               "#34d399", "#10b981", "#f87171", "#fca5a5", "#ef4444", "#fbbf24",
               "#fde68a", "#f59e0b", "#eab308", "#fb923c", "#f97316", "#a78bfa",
               "#c084fc", "#8b5cf6", "#a855f7", "#22d3ee", "#06b6d4", "#f472b6",
               "#ec4899"]

HEX = re.compile(r"#[0-9a-fA-F]{6}(?![0-9a-fA-F])")


def _alpha_concat(s, end):
    """True if the literal ending at `end` is followed by  "+  /  '+  /  +"..  (alpha concat)."""
    rest = s[end:end + 6]
    return bool(re.match(r"""^["'`]?\s*\+""", rest))


def replace_colors(seg, accent=False):
    out, last, n = [], 0, 0
    for m in HEX.finditer(seg):
        hx = m.group(0).lower()
        if hx in NEUTRAL and not accent:
            rep = NEUTRAL[hx]
        elif accent and hx in ACCENT_TEXT:
            rep = f"var(--t-{hx[1:]}, {hx})"
        else:
            continue
        if _alpha_concat(seg, m.end()):
            continue
        # skip `${...}` hex directly followed by template alpha, e.g. `#1e293b${a}`
        if seg[m.end():m.end() + 2] == "${":
            continue
        out.append(seg[last:m.start()]); out.append(rep); last = m.end(); n += 1
    out.append(seg[last:])
    return "".join(out), n


def scan_balanced(s, i):
    """s[i] == '{'. Return index just past the matching '}' (string/template aware)."""
    depth, j, L = 0, i, len(s)
    stack = []  # template-literal nesting: depth at which ${ opened
    while j < L:
        c = s[j]
        if c in "\"'":
            q = c; j += 1
            while j < L and s[j] != q:
                if s[j] == "\\": j += 1
                j += 1
        elif c == "`":
            j += 1
            while j < L and s[j] != "`":
                if s[j] == "\\": j += 2; continue
                if s[j] == "$" and j + 1 < L and s[j + 1] == "{":
                    k = scan_balanced(s, j + 1); j = k; continue
                j += 1
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return L


def split_props(body):
    """Yield (key, start, end) of each top-level `key: value` in an object body."""
    depth, j, L, start = 0, 0, len(body), 0
    parts = []
    while j < L:
        c = body[j]
        if c in "\"'":
            q = c; j += 1
            while j < L and body[j] != q:
                if body[j] == "\\": j += 1
                j += 1
        elif c == "`":
            j += 1
            while j < L and body[j] != "`":
                if body[j] == "\\": j += 2; continue
                if body[j] == "$" and j + 1 < L and body[j + 1] == "{":
                    j = scan_balanced(body, j + 1); continue
                j += 1
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append((start, j)); start = j + 1
        j += 1
    parts.append((start, L))
    for a, b in parts:
        m = re.match(r"\s*([A-Za-z_$][\w$]*|\"[^\"]+\"|'[^']+')\s*:", body[a:b])
        yield (m.group(1).strip("\"'") if m else None), a, b


def transform_style_obj(obj):
    """obj is the inner object text including its braces: {...}"""
    body = obj[1:-1]
    new, n = replace_colors(body)
    # accent text: only top-level `color:` props
    pieces, last, n2 = [], 0, 0
    for key, a, b in split_props(new):
        if key == "color":
            seg, k = replace_colors(new[a:b], accent=True)
            pieces.append(new[last:a]); pieces.append(seg); last = b; n2 += k
    pieces.append(new[last:])
    return "{" + "".join(pieces) + "}", n + n2


def main():
    args = sys.argv[1:]
    path = args[0]
    dry = "--dry" in args
    excl = []
    for i, a in enumerate(args):
        if a == "--exclude":
            s, e = args[i + 1].split("-"); excl.append((int(s), int(e)))
    src = open(path, encoding="utf-8").read()
    # line-start offsets for exclusion test
    starts = [0]
    for m in re.finditer("\n", src): starts.append(m.end())
    def line_of(off):
        lo, hi = 0, len(starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if starts[mid] <= off: lo = mid
            else: hi = mid - 1
        return lo + 1
    def excluded(off):
        ln = line_of(off)
        return any(s <= ln <= e for s, e in excl)

    out, last, total, objs = [], 0, 0, 0
    pat = re.compile(r"style=\{\{|\.style\.([A-Za-z]+)\s*=\s*(\"#[0-9a-fA-F]{6}\")")
    pos = 0
    while True:
        m = pat.search(src, pos)
        if not m: break
        if excluded(m.start()):
            pos = m.end(); continue
        if m.group(0).startswith("style="):
            ob = m.start() + len("style={")
            end = scan_balanced(src, ob)
            new, n = transform_style_obj(src[ob:end])
            out.append(src[last:ob]); out.append(new); last = end; pos = end
            total += n; objs += 1 if n else 0
        else:
            prop, lit = m.group(1), m.group(2)
            hx = lit.strip('"').lower()
            rep = NEUTRAL.get(hx)
            if rep is None and prop == "color" and hx in ACCENT_TEXT:
                rep = f"var(--t-{hx[1:]}, {hx})"
            if rep:
                s = m.start(2)
                out.append(src[last:s]); out.append(f'"{rep}"'); last = m.end(2); total += 1
            pos = m.end()
    out.append(src[last:])
    res = "".join(out)
    print(f"{path}: {total} colour replacements in {objs} style objects")
    if not dry:
        open(path, "w", encoding="utf-8").write(res)


if __name__ == "__main__":
    main()
