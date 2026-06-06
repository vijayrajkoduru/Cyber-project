"""_cleanup_recon.py — mechanical removal of chain_handoff from Recon scanners.

Per owner directive 2026-06-06 "if you chain it will go hacking dont do that",
remove all chain_handoff plumbing from the 25 Recon scanners that adopted it
in Phases 1+2+3 of the VL-METHOD experiment. The chain registry itself stays
in tools/_methodology/ for Password/Webapp modules — only Recon strips it.

What gets removed:
  1. def _r_chain_handoff(s):  ...  function definition
  2. _r_chain_handoff entry from FINDING_RULES / _INLINE_RULES lists
  3. async def _chain_callable function at bottom of file (if present)
  4. from tools._methodology import chain_registry  import
  5. chain_registry.register("name", _chain_callable) call
  6. Decorative comment blocks above the chain registration

Idempotent: safe to run multiple times.
Run from project root: python scripts/_cleanup_recon.py
"""
import re
from pathlib import Path

RECON_DIR = Path(__file__).resolve().parent.parent / "tools" / "recon"

# Files that import chain_handoff or chain_registry (from the audit).
TARGETS = [
    "tier1_passive/asn.py",
    "tier1_passive/crt_search.py",
    "tier1_passive/passive_dns.py",
    "tier1_passive/reverse_ip.py",
    "tier1_passive/whois.py",
    "tier2_dns/dns_records.py",
    "tier2_dns/email_security.py",
    "tier2_dns/subdomain_takeover.py",
    "tier2_dns/zone_transfer.py",
    "tier3_subdomain/amass_passive.py",
    "tier3_subdomain/subdomain_bruteforce.py",
    "tier3_subdomain/wayback_subdomain_extract.py",
    "tier5_web/api_endpoint_brute.py",
    "tier5_web/cors_misconfig.py",
    "tier5_web/graphql_intro_check.py",
    "tier5_web/http_banner.py",
    "tier5_web/security_headers.py",
    "tier5_web/ssl_tls_audit.py",
    "tier5_web/tech_stack_detect.py",
    "tier5_web/waf_cdn_detect.py",
    "tier6_cloud/s3_bucket_enum.py",
    "tier9_network/service_version_detect.py",
    "tier9_network/smb_netbios_enum.py",
    "tier9_network/snmp_enum.py",
    "tier9_network/tcp_port_scan.py",
]


def _strip_function_def(text: str, func_name: str) -> str:
    """Remove `def func_name(...):` and all its body. Body ends when the next
    line is at indent level 0 (top-level def/class/import/blank etc.)."""
    lines = text.splitlines(keepends=True)
    out = []
    i = 0
    n = len(lines)
    while i < n:
        ln = lines[i]
        if re.match(rf"^def\s+{re.escape(func_name)}\s*\(", ln) or \
           re.match(rf"^async\s+def\s+{re.escape(func_name)}\s*\(", ln):
            # Skip the def line + all its indented body
            i += 1
            while i < n:
                nxt = lines[i]
                # Stop at next top-level def/class/import/etc. or non-blank zero-indent
                if nxt.strip() == "":
                    i += 1
                    continue
                if re.match(r"^[a-zA-Z_@#]", nxt):
                    break
                i += 1
            continue
        out.append(ln)
        i += 1
    return "".join(out)


def _strip_from_list_literal(text: str, name: str) -> str:
    """Remove `name` from list literals like [a, b, name, c] -> [a, b, c]."""
    # Handle ", name" / "name, " / "[name]" / "[name, " patterns
    pat1 = re.compile(rf",\s*{re.escape(name)}\b")
    pat2 = re.compile(rf"\b{re.escape(name)}\s*,\s*")
    text = pat1.sub("", text)
    text = pat2.sub("", text)
    # Handle [name] (alone) - replace with []
    pat3 = re.compile(rf"\[\s*{re.escape(name)}\s*\]")
    text = pat3.sub("[]", text)
    return text


def _strip_chain_registry_block(text: str) -> str:
    """Remove the bottom-of-file chain registration: the import + register call
    + any decorative comment block right above it."""
    # Remove `from tools._methodology import chain_registry` line
    text = re.sub(r"^from\s+tools\._methodology\s+import\s+chain_registry.*\n",
                   "", text, flags=re.MULTILINE)
    # Remove `chain_registry.register(...)` call (one line)
    text = re.sub(r"^chain_registry\.register\([^\n]*\)\s*\n",
                   "", text, flags=re.MULTILINE)
    # Remove decorative comment block: a run of lines starting with #= or
    # # at module bottom that introduces the chain section. Match any
    # contiguous "# ..." comment block followed by blank line.
    text = re.sub(
        r"^#\s*={5,}\s*\n(?:^#.*\n)*^#\s*={5,}\s*\n+",
        "", text, flags=re.MULTILINE,
    )
    # Strip "# Chain registry registration ..." comments that may remain
    text = re.sub(
        r"^#\s*Chain[\s\S]*?(?=^\S|\Z)",
        "", text, flags=re.MULTILINE,
    )
    # Collapse 3+ blank lines into 2
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    return text


def process_file(path: Path) -> tuple[bool, str]:
    """Returns (changed, summary)."""
    original = path.read_text(encoding="utf-8")
    text = original

    actions = []

    # 1. Strip _r_chain_handoff from finding-rule lists
    if "_r_chain_handoff" in text:
        before = text
        text = _strip_from_list_literal(text, "_r_chain_handoff")
        if text != before:
            actions.append("removed _r_chain_handoff from rule list")

    # 2. Strip def _r_chain_handoff function body
    if "def _r_chain_handoff" in text:
        text = _strip_function_def(text, "_r_chain_handoff")
        actions.append("deleted _r_chain_handoff function")

    # 3. Strip _chain_callable function body
    if "_chain_callable" in text:
        text = _strip_function_def(text, "_chain_callable")
        actions.append("deleted _chain_callable function")

    # 4. Strip chain_registry import + register call + decorative comments
    if "chain_registry" in text or "_methodology" in text:
        before = text
        text = _strip_chain_registry_block(text)
        if text != before:
            actions.append("removed chain_registry registration")

    # 5. Trim trailing whitespace + collapse runs of blank lines
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    text = text.rstrip() + "\n"

    if text != original:
        path.write_text(text, encoding="utf-8")
        return True, " | ".join(actions)
    return False, "no change"


def main():
    changed = 0
    skipped = 0
    for rel in TARGETS:
        p = RECON_DIR / rel
        if not p.exists():
            print(f"  MISSING: {rel}")
            skipped += 1
            continue
        was_changed, summary = process_file(p)
        status = "CHANGED" if was_changed else "ok-already"
        print(f"  {status:11} {rel:50} {summary}")
        if was_changed:
            changed += 1

    print()
    print(f"Total: {changed} changed, {len(TARGETS)-changed-skipped} unchanged, {skipped} missing")


if __name__ == "__main__":
    main()
