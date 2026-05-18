"""Generic payload library generator (streaming + multi-point salvage)."""
import json, os, re, sys
import anthropic

CONFIGS = {
    "sqli": {
        "count": 200, "max_tokens": 32000, "var": "SQL_PAYLOADS",
        "prompt": """Generate 200 SQL injection payloads. Mix: boolean-blind 40, error-based 35, time-based 35 (use {N} for seconds), union 30, stacked 20, order-by 15, waf-bypass 25. DBMS: MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MongoDB.

Each item EXACTLY 6 keys: payload, dbms, category, matcher (Python regex <80 chars; for time use "TIME>{N}"), severity (CRITICAL|HIGH), cvss.

OUTPUT: ONLY JSON array. Start [ end ]. No prose. Keep ALL strings concise."""
    },
    "xss": {
        "count": 150, "max_tokens": 24000, "var": "XSS_PAYLOADS",
        "prompt": """Generate 150 XSS payloads. Mix: html 40, attribute 30, js-string-break 25, url 15, dom-clobbering 15, waf-bypass 20, mutation 5.

Each item EXACTLY 5 keys: payload, context (html|attribute|js|url|dom|mutation|polyglot), matcher (Python regex <60 chars matching echoed payload), severity (CRITICAL|HIGH), cvss.

OUTPUT: ONLY JSON array. Start [ end ]. NO prose, NO notes field. Keep ALL strings concise."""
    },
    "lfi": {
        "count": 120, "max_tokens": 18000, "var": "LFI_PAYLOADS",
        "prompt": """Generate 120 LFI / path-traversal payloads. Mix: linux-passwd 35, windows-ini 15, php-filter 15, proc-self 10, encoded-bypass 20, double-encoded 15, null-byte 5, log-poison 5.

Each item EXACTLY 5 keys: payload, target_os (linux|windows|any), category, matcher (Python regex <60 chars), severity, cvss.

OUTPUT: ONLY JSON array. No prose. Concise strings."""
    },
    "force_browse": {
        "count": 500, "max_tokens": 28000, "var": "FORCE_BROWSE_PATHS",
        "prompt": """Generate 500 sensitive paths for force-browse scanning. Cover: backup files, config exposures (wp-config, .env), dev/debug, admin panels, API debug, source-control (.git/.svn), CI/build, log files, temp/upload, common app paths, exposed CMS, IDE/editor (.idea/.vscode), cloud configs, secret stores.

Each item EXACTLY 3 keys: path (with leading /), category (short snake_case), severity (HIGH|MEDIUM|LOW).

OUTPUT: ONLY JSON array. Concise. No reason field."""
    },
}


def salvage(raw):
    """Multi-point salvage — walks backwards finding the longest valid JSON prefix."""
    raw = re.sub(r"^```(?:json)?\s*", "", raw.strip())
    raw = re.sub(r"\s*```$", "", raw)
    try:
        return json.loads(raw), False
    except json.JSONDecodeError:
        pass
    # Walk backwards through all "}," positions, try parsing prefix + "]"
    end_positions = [m.end() - 1 for m in re.finditer(r"\},", raw)]
    end_positions.reverse()
    for pos in end_positions:
        candidate = raw[:pos+1] + "]"
        try:
            result = json.loads(candidate)
            if isinstance(result, list) and len(result) > 10:
                return result, True
        except json.JSONDecodeError:
            continue
    return None, False


def main():
    kind = sys.argv[1] if len(sys.argv) > 1 else ""
    if kind not in CONFIGS:
        sys.exit(f"Usage: gen_payloads.py {list(CONFIGS.keys())}")
    cfg = CONFIGS[kind]
    print(f"=== {kind} ({cfg['count']} items, max_tokens={cfg['max_tokens']}, streaming) ===")

    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY missing")

    client = anthropic.Anthropic()
    raw_chunks = []
    in_tok = out_tok = 0
    last_dot = 0
    with client.messages.stream(
        model="claude-sonnet-4-6",
        max_tokens=cfg["max_tokens"],
        messages=[{"role": "user", "content": cfg["prompt"]}],
    ) as stream:
        for text in stream.text_stream:
            raw_chunks.append(text)
            total = sum(len(c) for c in raw_chunks)
            if total // 5000 > last_dot:
                print(".", end="", flush=True)
                last_dot = total // 5000
        final = stream.get_final_message()
        in_tok = final.usage.input_tokens
        out_tok = final.usage.output_tokens
    print()

    raw = "".join(raw_chunks)
    items, salvaged = salvage(raw)
    if items is None:
        open(f"/tmp/{kind}_raw.txt", "w").write(raw)
        sys.exit(f"Multi-point salvage failed for {kind}. Saved /tmp/{kind}_raw.txt ({len(raw)} bytes)")
    if salvaged:
        print(f"  ⚠ truncated — multi-point salvage recovered {len(items)} complete items")

    out = f"/tmp/vl_payloads/{kind}.py"
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        f.write(f'"""{kind} payload library — generated dev-time by Claude.\n\n'
                f'Regenerate via tools/_gen/gen_payloads.py {kind}. Zero runtime cost.\n"""\n\n'
                f'{cfg["var"]} = ')
        json.dump(items, f, indent=2, ensure_ascii=False)
        f.write("\n")

    cost = (in_tok * 3 + out_tok * 15) / 1_000_000
    print(f"  ✓ wrote {len(items)} items to {out}")
    print(f"  tokens: {in_tok} in, {out_tok} out  |  cost: ~{cost:.3f} USD")


if __name__ == "__main__":
    main()
