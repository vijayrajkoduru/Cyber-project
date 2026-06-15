"""Offline curation-quality validator.

Curation FP-risk lives in the DATA (detection logic is unchanged), so this audits
every curated pool built in the AI-curation waves for:
  - duplicates / empties / junk
  - schema + detection-marker conformance (so detection still fires)
  - false-positive risk: every regex / takeover-fingerprint is run against a
    BENIGN corpus; anything that matches normal code/text is flagged.
  - vuln reference data: KEV keys are EXACT CVE-IDs, CWE keys exact CWE ids.

Run:  python scripts/validate_curation.py
Exit non-zero if any ERROR-level issue is found (WARN is advisory).
"""
from __future__ import annotations

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAY = os.path.join(ROOT, "tools", "_payloads")

ERRORS: list[str] = []
WARNS: list[str] = []


def err(m): ERRORS.append(m)
def warn(m): WARNS.append(m)


def _load(path):
    with open(path, "r", encoding="utf-8") as f:
        if path.endswith(".json"):
            return json.load(f)
        return [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]


# Benign corpus: normal strings a regex must NOT match (else it's FP-prone).
BENIGN = [
    "const userName = getUser();", "function calculateTotal(items) {",
    "import React from 'react';", "https://example.com/api/v1/users",
    "the quick brown fox jumps over the lazy dog",
    "2026-06-15T12:00:00Z", "version: 1.2.3-beta.4",
    "550e8400-e29b-41d4-a716-446655440000",            # uuid
    "d41d8cd98f00b204e9800998ecf8427e",                # md5-looking hex
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",  # sha256 hex
    "SGVsbG8gd29ybGQgdGhpcyBpcyBub3JtYWwgdGV4dA==",    # base64 of normal text
    "/usr/local/bin/python3", "C:\\Users\\dev\\project",
    "color: #3b9eff; font-size: 14px;", "TODO: refactor this later",
    "user_id = 12345", "email_field = 'message'", "status: active",
    "lorem ipsum dolor sit amet consectetur", "package-lock.json",
    "GET /health HTTP/1.1", "Content-Type: application/json",
    "androidx.appcompat.app.AppCompatActivity",         # normal android class
    "com.example.myapp.MainActivity", "0123456789",
    "true", "false", "null", "undefined", "AABBCCDD",
]
# Generic terms that make a takeover fingerprint / pattern FP-prone.
GENERIC_FP = ["404", "not found", "page not found", "error", "403", "forbidden",
              "bad request", "no such", "does not exist"]


def _compile(pat):
    try:
        return re.compile(pat, re.IGNORECASE), None
    except re.error as e:
        return None, str(e)


def _dupes(items):
    seen, dup = set(), 0
    for x in items:
        k = json.dumps(x, sort_keys=True) if isinstance(x, (dict, list)) else str(x).strip().lower()
        if k in seen:
            dup += 1
        seen.add(k)
    return dup


def _extract_regexes(obj):
    """Yield (label, regex_string) from a regex pool of varied shape."""
    out = []
    def walk(o, label):
        if isinstance(o, str):
            out.append((label, o))
        elif isinstance(o, dict):
            for k in ("regex", "pattern", "re"):
                if isinstance(o.get(k), str):
                    out.append((str(o.get("name", o.get("id", label))), o[k]))
                    return
            for k, v in o.items():
                walk(v, f"{label}.{k}")
        elif isinstance(o, list):
            for i, v in enumerate(o):
                walk(v, f"{label}[{i}]")
    walk(obj, "root")
    return out


# ── checks per pool ──────────────────────────────────────────────────────────
def check_wordlist(mod, name):
    path = os.path.join(PAY, mod, name)
    if not os.path.exists(path):
        err(f"{mod}/{name}: MISSING"); return
    items = _load(path)
    if not items:
        err(f"{mod}/{name}: EMPTY"); return
    d = _dupes(items)
    blank = sum(1 for x in items if not str(x).strip())
    if d: warn(f"{mod}/{name}: {d} duplicate lines")
    if blank: warn(f"{mod}/{name}: {blank} blank lines")
    print(f"  {mod}/{name}: {len(items)} lines, {d} dup")


def check_markers(mod, name, payload_keys=("payload", "prompt", "query", "url", "body")):
    """Payload pool whose detection relies on a marker — verify markers exist."""
    path = os.path.join(PAY, mod, name)
    if not os.path.exists(path):
        err(f"{mod}/{name}: MISSING"); return
    data = _load(path)
    if isinstance(data, dict):
        data = data.get("payloads") or data.get("signatures") or list(data.values())
    if not isinstance(data, list) or not data:
        warn(f"{mod}/{name}: not a non-empty list (shape={type(data).__name__})"); return
    d = _dupes(data)
    if d: warn(f"{mod}/{name}: {d} duplicate entries")
    no_payload = no_marker = 0
    for e in data:
        if not isinstance(e, dict):
            continue
        if not any(str(e.get(k, "")).strip() for k in payload_keys):
            no_payload += 1
        mk = e.get("markers") or e.get("marker") or e.get("matcher")
        if mk is not None and not (mk if isinstance(mk, str) else "".join(map(str, mk))).strip():
            no_marker += 1
    if no_payload: warn(f"{mod}/{name}: {no_payload} entries with no payload/prompt text")
    if no_marker: warn(f"{mod}/{name}: {no_marker} entries with empty marker")
    print(f"  {mod}/{name}: {len(data)} entries, {d} dup, {no_payload} no-payload, {no_marker} empty-marker")


def check_regex_fp(mod, name):
    path = os.path.join(PAY, mod, name)
    if not os.path.exists(path):
        err(f"{mod}/{name}: MISSING"); return
    obj = _load(path)
    rgx = _extract_regexes(obj)
    if not rgx:
        warn(f"{mod}/{name}: no regexes extracted"); return
    bad = fp = 0
    for label, pat in rgx:
        c, e = _compile(pat)
        if c is None:
            err(f"{mod}/{name}: regex '{label}' won't compile: {e}"); bad += 1; continue
        hits = [b for b in BENIGN if c.search(b)]
        if hits:
            fp += 1
            warn(f"{mod}/{name}: regex '{label}' matches benign input -> FP risk (e.g. {hits[0]!r})")
    print(f"  {mod}/{name}: {len(rgx)} regexes, {bad} broken, {fp} FP-risk")


def check_substring_markers(mod, name):
    """Pool matched as LITERAL substrings (m in text) — so regex metachars like
    \\n or .* mean a mis-authored marker that can never match real code."""
    path = os.path.join(PAY, mod, name)
    if not os.path.exists(path):
        err(f"{mod}/{name}: MISSING"); return
    obj = _load(path)
    markers = []
    for v in (obj.values() if isinstance(obj, dict) else [obj]):
        if isinstance(v, list):
            markers += [m for m in v if isinstance(m, str)]
    bad = [m for m in markers if "\n" in m or ".*" in m or m != m.strip()]
    dup = _dupes([m.lower() for m in markers])
    if bad: warn(f"{mod}/{name}: {len(bad)} markers contain regex syntax (never match as substring): {bad[:2]}")
    if dup: warn(f"{mod}/{name}: {dup} duplicate markers")
    print(f"  {mod}/{name}: {len(markers)} substring markers, {len(bad)} mis-authored, {dup} dup")


def check_takeover_fingerprints():
    path = os.path.join(PAY, "network", "subdomain_takeover_sigs.json")
    if not os.path.exists(path):
        err("network/subdomain_takeover_sigs.json: MISSING"); return
    obj = _load(path)
    sigs = obj.get("signatures") if isinstance(obj, dict) else obj
    generic = 0
    for s in sigs or []:
        fp = (s.get("fingerprint") or "").strip().lower() if isinstance(s, dict) else ""
        if not fp:
            warn("network: a signature has empty fingerprint"); continue
        if fp in GENERIC_FP or len(fp) < 12:
            generic += 1
            warn(f"network: generic/short takeover fingerprint -> FP risk: {fp!r}")
    print(f"  network/subdomain_takeover_sigs: {len(sigs or [])} sigs, {generic} generic/short")


def check_vuln_reference():
    base = os.path.join(PAY, "vuln")
    kev = os.path.join(base, "kev_crossref.json")
    if os.path.exists(kev):
        d = _load(kev)
        keys = [k for k in d.keys() if k != "_meta"] if isinstance(d, dict) else []
        bad = [k for k in keys if not re.fullmatch(r"CVE-\d{4}-\d{4,}", k)]
        if bad: err(f"vuln/kev_crossref: {len(bad)} keys are NOT exact CVE-IDs (FP risk): {bad[:3]}")
        print(f"  vuln/kev_crossref: {len(keys)} CVE keys, {len(bad)} non-CVE-id")
    cwe = os.path.join(base, "cwe_catalog.json")
    if os.path.exists(cwe):
        d = _load(cwe)
        keys = [k for k in d.keys() if k != "_meta"] if isinstance(d, dict) else []
        bad = [k for k in keys if not re.fullmatch(r"CWE-\d+", k)]
        if bad: warn(f"vuln/cwe_catalog: {len(bad)} keys not CWE-ids: {bad[:3]}")
        print(f"  vuln/cwe_catalog: {len(keys)} CWE keys, {len(bad)} non-CWE-id")


def main():
    print("== wordlists ==")
    for mod, name in [("auth_attacks", "jwt_secrets.txt"),
                      ("supply_chain", "pypi_top_packages.txt"),
                      ("supply_chain", "npm_top_packages.txt"),
                      ("cloud", "bucket_prefixes.txt"),
                      ("cloud", "bucket_suffixes.txt")]:
        check_wordlist(mod, name)

    print("\n== marker-based payload pools ==")
    for name in ["xss_extra_payloads.json", "sqli_extra_payloads.json", "ssti_payloads.json",
                 "nosql_payloads.json", "lfi_extra_paths.json", "ssrf_extra_targets.json",
                 "cmd_injection_extra.json", "xxe_extra_payloads.json", "graphql_payloads.json",
                 "open_redirect_extra.json", "file_upload_payloads.json"]:
        check_markers("webapp", name)
    for name in ["prompt_injection.json", "jailbreaks.json", "pii_extraction.json",
                 "encoding_evasion.json", "system_prompt_leak.json"]:
        check_markers("ai_llm", name)

    print("\n== regex pools (FP audit vs benign corpus) ==")
    for name in ["secrets_regex.json", "pii_patterns.json", "weak_crypto.json"]:
        check_regex_fp("mobile", name)
    check_regex_fp("container_k8s", "secret_patterns.json")

    print("\n== substring-marker pools (literal match, not regex) ==")
    check_substring_markers("mobile", "insecure_prng.json")

    print("\n== takeover fingerprints ==")
    check_takeover_fingerprints()

    print("\n== vuln reference data ==")
    check_vuln_reference()

    print("\n" + "=" * 60)
    print(f"ERRORS: {len(ERRORS)}   WARNINGS: {len(WARNS)}")
    for e in ERRORS:
        print("  ERROR:", e)
    for w in WARNS[:60]:
        print("  WARN :", w)
    if len(WARNS) > 60:
        print(f"  ... and {len(WARNS) - 60} more warnings")
    sys.exit(1 if ERRORS else 0)


if __name__ == "__main__":
    main()
