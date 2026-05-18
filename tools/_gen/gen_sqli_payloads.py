"""One-shot generator: 300 curated SQL injection payloads.

Usage (inside backend container, .env must have ANTHROPIC_API_KEY):
    python3 tools/_gen/gen_sqli_payloads.py

Output: tools/_payloads/sqli.py  — Python list ready to import.
"""
import json, os, re, sys, textwrap
import anthropic

OUT = "tools/_payloads/sqli.py"

PROMPT = """You are a senior application security researcher building a payload \
library for an automated DAST scanner. Generate a curated, deduplicated list of \
SQL injection payloads.

REQUIREMENTS:
- Exactly 300 payloads
- Mix categories: boolean-blind 50, error-based 50, time-based 50 (use {N} for seconds), \
union-based 50, stacked queries 30, second-order/order-by 30, WAF-bypass 40
- DBMS: MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MongoDB
- Each item has EXACTLY these 6 keys:
  payload     : raw injection string
  dbms        : one of {MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MongoDB, Generic}
  category    : one of {boolean, error, time, union, stacked, order_by, waf_bypass, nosql}
  matcher     : Python regex (raw, no quotes) detecting the bug in the response body.
                For time-based use the literal sentinel "TIME>{N}"
  severity    : "CRITICAL" or "HIGH"
  cvss        : CVSS 3.1 numeric score as string (e.g. "9.8")

OUTPUT: ONLY a valid JSON array. No prose, no markdown, no code fences. \
Start with [ and end with ]. UTF-8 only. No trailing commas.

START YOUR RESPONSE WITH ["""


def main():
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        sys.exit("ERROR: ANTHROPIC_API_KEY missing")
    print(f"Auth OK (key length={len(key)}). Calling Claude Sonnet 4.6...")

    msg = anthropic.Anthropic().messages.create(
        model="claude-sonnet-4-6",
        max_tokens=16000,
        messages=[{"role":"user","content":PROMPT}],
    )
    raw = msg.content[0].text.strip()
    raw = re.sub(r"^```(?:json)?\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)

    try:
        payloads = json.loads(raw)
    except json.JSONDecodeError as e:
        open("/tmp/sqli_raw.txt","w").write(raw)
        sys.exit(f"JSON parse failed: {e}. Raw saved to /tmp/sqli_raw.txt")

    if not isinstance(payloads, list) or len(payloads) < 100:
        sys.exit(f"Got {type(payloads).__name__} of size {len(payloads) if isinstance(payloads,list) else 'N/A'}")

    required = {"payload","dbms","category","matcher","severity","cvss"}
    for i,p in enumerate(payloads):
        missing = required - set(p.keys())
        if missing:
            sys.exit(f"Payload #{i} missing keys: {missing}")

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        f.write('"""SQL Injection payload library — generated dev-time by Claude.\n\n'
                'Regenerate via tools/_gen/gen_sqli_payloads.py. Zero runtime API cost.\n"""\n\n'
                'SQL_PAYLOADS = ')
        json.dump(payloads, f, indent=2, ensure_ascii=False)
        f.write("\n")

    in_tok = msg.usage.input_tokens
    out_tok = msg.usage.output_tokens
    cost = (in_tok * 3 + out_tok * 15) / 1_000_000
    dbms_dist = {}
    for p in payloads:
        dbms_dist[p["dbms"]] = dbms_dist.get(p["dbms"], 0) + 1
    print(f"\n✓ Wrote {len(payloads)} payloads to {OUT}")
    print(f"  Tokens: {in_tok} in, {out_tok} out")
    print(f"  Cost:   ~${cost:.3f}")
    print(f"  DBMS:   {dbms_dist}")


if __name__ == "__main__":
    main()
