#!/usr/bin/env python3
"""ENTERPRISE-UI light-mode safety net.

Some colours live in data tables and are alpha-concatenated (`${c.color}50`), so they
cannot become CSS variables. React writes them into the inline style attribute,
which the browser serialises as e.g. `color: rgb(74, 222, 128)`. This script
collects every such hex in App.js (outside the logged-out pages) and emits
attribute-selector rules, scoped to .vl-light, that swap:
  bright text colour   -> a darker readable variant
  dark background      -> translucent tint of the same hue (or a neutral surface)
  dark border colour   -> translucent border of the same hue
Output: the CSS text printed to stdout, to be pasted between the
/* LIGHT-NET:BEGIN */ and /* LIGHT-NET:END */ markers in APP_CSS (done with --write).

Usage: theme_light_net.py src/App.js --exclude 1137-1818 [--write]
"""
import re
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from theme_pass2 import rgb, hls, bucket, chroma  # noqa: E402

TINT = {"red": "239,68,68", "orange": "249,115,22", "amber": "234,179,8", "green": "34,197,94",
        "cyan": "6,182,212", "blue": "59,130,246", "purple": "168,85,247", "pink": "236,72,153"}


def dark_text(h):
    import colorsys
    hu, l, s = hls(h)
    r, g, b = colorsys.hls_to_rgb(hu, 0.36, min(max(s, 0.55), 0.8))
    return "#%02x%02x%02x" % (round(r * 255), round(g * 255), round(b * 255))


def rgbs(h):
    r, g, b = rgb(h)
    return f"rgb({round(r*255)}, {round(g*255)}, {round(b*255)})"


def main():
    a = sys.argv[1:]
    path = a[0]
    excl = [tuple(map(int, a[i + 1].split("-"))) for i, x in enumerate(a) if x == "--exclude"]
    lines = open(path, encoding="utf-8").read().split("\n")
    hexes = set()
    for i, l in enumerate(lines, 1):
        if any(s <= i <= e for s, e in excl) or "LIGHT-NET" in l: continue
        hexes.update(h.lower() for h in re.findall(r"#[0-9a-fA-F]{6}(?![0-9a-fA-F])", l))
    rules = []
    for h in sorted(hexes):
        hu, l, s = hls(h)
        c = chroma(h)
        r = rgbs(h)
        if c >= 0.16 and l > 0.5:          # bright accent used as text
            sel = f'.vl-light [style^="color: {r}"],.vl-light [style*="; color: {r}"]'
            rules.append(f"{sel}{{color:{dark_text(h)}!important}}")
        if l < 0.3:                        # dark background / border
            b = bucket(h)
            bg = f"rgba({TINT[b]},.10)" if b else "var(--surface2)"
            if b == "blue" and l < 0.14: bg = "var(--surface2)"
            sel = (f'.vl-light [style^="background: {r}"],.vl-light [style*="; background: {r}"],'
                   f'.vl-light [style^="background-color: {r}"],.vl-light [style*="; background-color: {r}"]')
            rules.append(f"{sel}{{background:{bg}!important}}")
            bd = f"rgba({TINT[b]},.35)" if b else "var(--border)"
            rules.append(f'.vl-light [style*="solid {r}"]{{border-color:{bd}!important}}')
    css = "\n".join("  " + x for x in rules)
    if "--write" in a:
        src = open(path, encoding="utf-8").read()
        s0 = src.index("/* LIGHT-NET:BEGIN */") + len("/* LIGHT-NET:BEGIN */")
        s1 = src.index("  /* LIGHT-NET:END */")
        src = src[:s0] + "\n" + css + "\n" + src[s1:]
        open(path, "w", encoding="utf-8").write(src)
    print(f"{len(rules)} rules for {len(hexes)} colours", file=sys.stderr)


if __name__ == "__main__":
    main()
