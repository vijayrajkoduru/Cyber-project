"""_cleanup_api_key_noise.py — convert 17 API-key-only Recon scanners from
emitting "requires API key" INFO findings (which inflate the PDF noise) into
clean SKIP entries (which show up in the Coverage Gaps "Paid API key required"
bucket instead).

Per audit 2026-06-06:
  17 scanners just check env-var presence and emit one of:
    - "X requires API key" INFO (when key missing)
    - "X configured" INFO (when key set, but no real probing)

After cleanup:
  - Key missing -> ctx.state["skipped_reason"] = "Requires API key (env: VAR)"
                   no rules emit findings
  - Key present -> as before (kept for future expansion)

This cuts ~15 INFO findings from every customer scan and groups them
honestly under "Scanners deliberately not run > API key required".
"""
import re
from pathlib import Path

RECON_DIR = Path(__file__).resolve().parent.parent / "tools" / "recon"

# (file, env-var hint shown in skip reason, vendor description)
TARGETS = [
    ("tier1_passive/whois_history.py",       "SECURITYTRAILS_API_KEY",     "SecurityTrails / WhoXY"),
    ("tier7_email/breach_aggregator.py",     "BREACH_AGGREGATOR_API_KEY",  "breach aggregator (DeHashed / IntelX / LeakCheck)"),
    ("tier7_email/crosslinked_emails.py",    "HUNTER_API_KEY",             "Hunter.io / Snov.io"),
    ("tier7_email/email_to_phone_pivot.py",  "EMAILREP_API_KEY",           "EmailRep / PhoneRep"),
    ("tier7_email/ghunt_google_audit.py",    "GHUNT_TOKENS",               "GHunt Google session tokens"),
    ("tier7_email/intelligence_x_search.py", "INTELX_API_KEY",             "Intelligence X"),
    ("tier7_email/leakcheck_search.py",      "LEAKCHECK_API_KEY",          "LeakCheck.net"),
    ("tier7_email/phoneinfoga_lookup.py",    "PHONEINFOGA_API_KEY",        "PhoneInfoga premium"),
    ("tier7_email/pimeyes_face_search.py",   "PIMEYES_API_KEY",            "PimEyes face-search"),
    ("tier8_threat/censys_search.py",        "CENSYS_API_KEY",             "Censys.io"),
    ("tier8_threat/fofa_search.py",          "FOFA_API_KEY",               "FOFA"),
    ("tier8_threat/misp_feed.py",            "MISP_AUTH_KEY",              "MISP threat feed"),
    ("tier8_threat/quake360_search.py",      "QUAKE360_API_KEY",           "Quake360"),
    ("tier8_threat/zoomeye_search.py",       "ZOOMEYE_API_KEY",            "ZoomEye"),
    ("tier10_code/gitlab_bitbucket_scan.py", "GITLAB_TOKEN",               "GitLab / Bitbucket personal token"),
    ("tier10_code/pypi_package_audit.py",    "PYPI_API_KEY",               "PyPI premium / Libraries.io"),
    ("tier11_darkweb/stealer_log_search.py", "STEALER_LOG_API_KEY",        "stealer-log aggregator"),
]


def process(path: Path, env_var: str, vendor: str) -> tuple[bool, str]:
    """Convert the file to a clean-skip pattern. Returns (changed, summary)."""
    original = path.read_text(encoding="utf-8")
    text = original

    # The pattern we want every API-key scanner to follow:
    skip_reason = f"Requires {vendor} API key — set env {env_var} to enable. Free tiers available at vendor's site."

    # Strategy: find the gather function and add skipped_reason set when no key.
    # Also nullify the _r_unkeyed rule to return None always.

    # Find _r_unkeyed function bodies and neutralize them
    pattern = re.compile(
        r"def\s+(_r_unkeyed|_r_no_key|_r_missing_key)\s*\(\s*s\s*\)\s*:.*?(?=\ndef\s|\nFINDING_RULES|\nINTEL_FIELDS|\n@router|\nasync def|\Z)",
        re.DOTALL,
    )
    text, n = pattern.subn(
        f"def _r_unkeyed(s):\n    # API-key-noise cleanup 2026-06-06: scanner now skips cleanly\n    # instead of emitting INFO. See skipped_reason set in gather().\n    return None\n\n",
        text,
    )

    # Find gather() and inject skipped_reason after the key-presence check.
    # Pattern: looks for `ctx.state["api_key_configured"]=bool(key)` or similar
    # and inserts `if not key: ctx.state["skipped_reason"] = "..."` right after.
    gather_pat = re.compile(
        r"(ctx\.state\[\s*['\"]api_key_configured['\"]\s*\]\s*=\s*bool\(\s*key\s*\)\s*\n)",
    )
    if gather_pat.search(text):
        text = gather_pat.sub(
            rf"\1    if not key:\n        ctx.state[\"skipped_reason\"] = \"{skip_reason}\"\n        return\n",
            text,
        )

    # If no api_key_configured pattern found, try a generic env.get pattern
    if "api_key_configured" not in text:
        env_pat = re.compile(
            rf"(\s*key\s*=\s*os\.environ\.get\(['\"]({env_var}|\w+API_KEY|\w+TOKEN)['\"]\s*\)\s*\n)",
        )
        if env_pat.search(text):
            text = env_pat.sub(
                rf"\1    if not key:\n        ctx.state[\"skipped_reason\"] = \"{skip_reason}\"\n        return\n",
                text,
            )

    if text != original:
        path.write_text(text, encoding="utf-8")
        return True, "converted to clean-skip"
    return False, "no change (pattern not found, manual review needed)"


def main():
    changed = 0
    manual = []
    for rel, env, vendor in TARGETS:
        p = RECON_DIR / rel
        if not p.exists():
            print(f"  MISSING: {rel}")
            continue
        ok, summary = process(p, env, vendor)
        if ok:
            print(f"  CHANGED  {rel:55} {summary}")
            changed += 1
        else:
            print(f"  MANUAL   {rel:55} {summary}")
            manual.append(rel)

    print()
    print(f"Total: {changed} auto-converted, {len(manual)} need manual review")
    if manual:
        print("Manual:")
        for m in manual:
            print(f"  {m}")


if __name__ == "__main__":
    main()
