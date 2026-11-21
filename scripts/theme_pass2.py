#!/usr/bin/env python3
"""ENTERPRISE-UI pass 2 — property-aware restyle of every inline style.

Runs over JSX style={{...}} objects and named style constants
(const fooStyle = {...}, const styles = {...}, const S = {...}). Decides what to
do with each colour by the CSS property it sits in:

  background*   dark neutral  -> var(--surface2)
                dark tinted   -> var(--tint-<hue>)        (translucent; works in both themes)
                blue accent   -> var(--accent)
                gradients     -> dark ones become var(--surface); coloured ones a solid colour
  border*       dark neutral  -> var(--border); dark tinted -> var(--bd-<hue>)
  color         white         -> var(--heading) unless the same object has a solid/coloured bg
                bright colour -> var(--t-xxxxxx, #xxxxxx) (darker variant generated for light mode)
                light grey    -> var(--text|--muted|--dim)
  boxShadow     glows ("0 0 ...") -> none
  fontWeight    800/900 -> 600
  letterSpacing >= 1 (px) -> 0.5
  fontFamily    monospace stacks -> var(--font-mono); other UI stacks -> var(--font-ui)

Never touches colours concatenated with an alpha suffix ("#abc123"+"22"), 8-digit
hex, variables, data tables, jsPDF/canvas code, or excluded line ranges.
Writes the generated --t-* light-mode overrides to scripts/theme_light_text.css.txt
(to paste into APP_CSS).

Usage: theme_pass2.py FILE [--exclude START-END ...] [--dry]
"""
import colorsys
import re
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from theme_codemod import scan_balanced, split_props, _alpha_concat  # noqa: E402

HEX = re.compile(r"#(?:[0-9a-fA-F]{6}|[0-9a-fA-F]{3})(?![0-9a-fA-F])")
STR = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')
GEN_T = {}   # hex -> light-mode darker variant


def rgb(h):
    h = h.lstrip("#")
    if len(h) == 3: h = "".join(c * 2 for c in h)
    return tuple(int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))


def hls(h):
    return colorsys.rgb_to_hls(*rgb(h))  # (hue, lightness, saturation)


def chroma(h):
    c = rgb(h); return max(c) - min(c)


def bucket(h):
    hu, l, s = hls(h)
    d = hu * 360
    if chroma(h) < 0.08: return None
    if d < 15 or d >= 345: return "red"
    if d < 40: return "orange"
    if d < 65: return "amber"
    if d < 170: return "green"
    if d < 200: return "cyan"
    if d < 250: return "blue"
    if d < 300: return "purple"
    return "pink"


def darken_for_light(h):
    hu, l, s = hls(h)
    r, g, b = colorsys.hls_to_rgb(hu, min(l, 0.38), min(s, 0.75))
    return "#%02x%02x%02x" % (round(r * 255), round(g * 255), round(b * 255))


def map_bg(h):
    hx = h.lower()
    if hx in ("#3b82f6", "#2563eb", "#1d4ed8"): return "var(--accent)"
    hu, l, s = hls(hx)
    if l < 0.3:
        b = bucket(hx)
        if b is None or (b == "blue" and l < 0.14):   # neutral / old navy base -> plain surface
            return "var(--surface2)"
        return f"var(--tint-{b})"
    return None


def map_border(h):
    hu, l, s = hls(h)
    if l < 0.36:
        b = bucket(h)
        return f"var(--bd-{b})" if b else "var(--border)"
    return None


def map_text(h, solid_bg):
    hx = h.lower()
    hu, l, s = hls(hx)
    if l > 0.93 and chroma(hx) < 0.1:            # white / near-white
        return None if solid_bg else "var(--heading)"
    if chroma(hx) < 0.16:                         # greys (slate greys are slightly blue)
        if l < 0.2: return None                   # black text on bright badge: keep
        return "var(--text)" if l > 0.78 else "var(--muted)" if l > 0.55 else "var(--dim)"
    if l > 0.5:                                   # bright accent text
        GEN_T[hx] = darken_for_light(hx)
        return f"var(--t-{hx[1:]}, {hx})"
    return None


BG_KEYS = {"background", "backgroundColor", "backgroundImage"}
BD_KEYS = {"border", "borderTop", "borderBottom", "borderLeft", "borderRight", "borderColor",
           "borderTopColor", "borderBottomColor", "borderLeftColor", "borderRightColor", "outline"}


def sub_hex(val, fn):
    out, last, n = [], 0, 0
    for m in HEX.finditer(val):
        if _alpha_concat(val, m.end()) or val[m.end():m.end() + 2] == "${":
            continue
        # skip hex that already sits inside a var() fallback
        if val[max(0, m.start() - 14):m.start()].rstrip().endswith(","):
            pre = val[:m.start()]
            if pre.rfind("var(") > pre.rfind(")"): continue
        rep = fn(m.group(0))
        if rep:
            out.append(val[last:m.start()]); out.append(rep); last = m.end(); n += 1
    out.append(val[last:])
    return "".join(out), n


def fix_gradient_literal(lit):
    """lit is a quoted string literal containing gradient(...)"""
    q, body = lit[0], lit[1:-1]
    stops = HEX.findall(body)
    vars_ = re.findall(r"var\(--[a-z0-9-]+", body)
    darks = [h for h in stops if hls(h)[1] < 0.3]
    if len(darks) == len(stops):                  # all dark (or only vars) -> flat surface
        return q + "var(--surface)" + q
    colored = [h for h in stops if hls(h)[1] >= 0.3]
    first = colored[0]
    return q + (map_bg(first) or first) + q


def solid_bg_of(props_text):
    m = re.search(r"\bbackground(?:Color)?\s*:\s*([^,}]+)", props_text)
    if not m: return False
    v = m.group(1)
    if "gradient" in v or "var(--accent)" in v: return True
    for h in HEX.findall(v):
        hu, l, s = hls(h)
        if s > 0.3 and 0.25 < l < 0.75: return True
    return False


def transform_obj(obj):
    body = obj[1:-1]
    solid = solid_bg_of(body)
    pieces, last, n = [], 0, 0
    for key, a, b in split_props(body):
        seg = body[a:b]
        if key is None:
            continue
        k = 0
        colon = seg.index(":") + 1
        head, val = seg[:colon], seg[colon:]
        vs = val.strip()
        if vs.startswith("{"):                    # nested style object (const S = {card:{...}})
            i0 = val.index("{"); i1 = scan_balanced(val, i0)
            inner, k = transform_obj(val[i0:i1])
            val = val[:i0] + inner + val[i1:]
        elif key in BG_KEYS:
            def g(m):
                return fix_gradient_literal(m.group(0)) if "gradient(" in m.group(0) else m.group(0)
            nv = STR.sub(g, val); k += nv != val; val = nv
            val, k2 = sub_hex(val, map_bg); k += k2
        elif key in BD_KEYS:
            val, k = sub_hex(val, map_border)
        elif key in ("color", "caretColor"):
            val, k = sub_hex(val, lambda h: map_text(h, solid))
        elif key in ("boxShadow", "textShadow"):
            nv = STR.sub(lambda m: m.group(0)[0] + "none" + m.group(0)[0]
                         if re.search(r"(^|,|\s)0 0 ", m.group(0)[1:-1]) else m.group(0), val)
            k = nv != val; val = nv
        elif key == "fontWeight":
            nv = re.sub(r"(?<![\w.])(800|900)(?![\w.])", "600", val); k = nv != val; val = nv
        elif key == "letterSpacing":
            def ls(m):
                x = float(m.group(0)); return "0.5" if x >= 1 else m.group(0)
            nv = re.sub(r"(?<![\w.\"'])\d+(\.\d+)?(?![\w.\"'%])", ls, val); k = nv != val; val = nv
        elif key == "fontFamily":
            def ff(m):
                s = m.group(0)
                if "var(" in s: return s
                return s[0] + ("var(--font-mono)" if re.search(r"mono|courier|consolas|menlo", s, re.I)
                               else "var(--font-ui)") + s[0]
            nv = STR.sub(ff, val); k = nv != val; val = nv
        if k:
            pieces.append(body[last:a]); pieces.append(head + val); last = b; n += k
    pieces.append(body[last:])
    return "{" + "".join(pieces) + "}", n


def main():
    args = sys.argv[1:]
    path, dry = args[0], "--dry" in args
    excl = [tuple(map(int, args[i + 1].split("-"))) for i, a in enumerate(args) if a == "--exclude"]
    src = open(path, encoding="utf-8").read()
    line_starts = [0] + [m.end() for m in re.finditer("\n", src)]
    import bisect
    def excluded(off):
        ln = bisect.bisect_right(line_starts, off)
        return any(s <= ln <= e for s, e in excl)
    pat = re.compile(r"style=\{\{|\bconst\s+(?:[A-Za-z_]\w*Style|styles|S)\s*=\s*\{")
    out, last, pos, total = [], 0, 0, 0
    while True:
        m = pat.search(src, pos)
        if not m: break
        if excluded(m.start()):
            pos = m.end(); continue
        ob = m.end() - 1 if not m.group(0).startswith("style=") else m.start() + len("style={")
        end = scan_balanced(src, ob)
        new, n = transform_obj(src[ob:end])
        out.append(src[last:ob]); out.append(new); last = end; pos = end; total += n
    out.append(src[last:])
    print(f"{path}: {total} property rewrites; {len(GEN_T)} generated light text colours")
    if not dry:
        open(path, "w", encoding="utf-8").write("".join(out))
        css = "".join(f"--t-{h[1:]}:{v};" for h, v in sorted(GEN_T.items()))
        open(__file__.rsplit("/", 1)[0] + "/theme_light_text.css.txt", "w").write(css + "\n")


if __name__ == "__main__":
    main()
