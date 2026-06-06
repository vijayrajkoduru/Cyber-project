"""_cleanup_recon2.py — second-pass cleanup of orphan decorative comment
blocks left behind by _cleanup_recon.py.

Strips trailing pattern:
    \n# ═════...
    # _chain_callable.
    # ═════...

Plus any all-comment-block at file bottom.
"""
import re
from pathlib import Path

RECON_DIR = Path(__file__).resolve().parent.parent / "tools" / "recon"

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


def process(path: Path) -> bool:
    original = path.read_text(encoding="utf-8")
    text = original

    # Strip ANY trailing block that's only comments / blank lines.
    # i.e., scan from the end and remove all-comment lines until we hit code.
    lines = text.splitlines()
    while lines:
        last = lines[-1].strip()
        if last == "" or last.startswith("#"):
            lines.pop()
            continue
        break
    text = "\n".join(lines) + "\n"

    # Collapse 3+ blank lines into 2
    text = re.sub(r"\n{4,}", "\n\n\n", text)

    if text != original:
        path.write_text(text, encoding="utf-8")
        return True
    return False


def main():
    changed = 0
    for rel in TARGETS:
        p = RECON_DIR / rel
        if not p.exists():
            continue
        if process(p):
            changed += 1
            print(f"  cleaned {rel}")
    print(f"\nTotal: {changed} files cleaned")


if __name__ == "__main__":
    main()
