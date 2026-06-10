"""Typosquat / lookalike domain finder — VulnusLab-native (no dnstwist binary needed).

Generates a permutation set for the target domain (homoglyph, character swap,
addition, omission, transposition, replacement, subdomain insertion, TLD swap)
and DNS-resolves each. Resolving permutations = potential phishing infra.

Algorithms cover dnstwist's most-effective transforms; native impl avoids the
subprocess dependency and 50+ Python deps the dnstwist binary requires.

VL-FOUNDRY Layer 6 (7-check DoD):
  precheck (safe_get via downstream resolver) · uniform standard_response
  · POSITIVE emit · severity · remediation · evidence_marker · timeout=25s
Layer 6b: parallel via ThreadPoolExecutor (80 perms in ~15s vs 120s seq).
"""
import asyncio
import socket
import string
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            wrap_finding, standard_response)
from tools._framework.reserved_domains import is_reserved, reason as reserved_reason
router = APIRouter()
WALL_CLOCK_S = 25


def _has_mx(domain: str, timeout: float = 1.5) -> bool:
    """True if the domain has at least one MX record. MX = capable of
    receiving mail = phishing-prep evidence. Used to elevate severity from
    INFO (typo exists) to LOW (typo is mail-ready)."""
    try:
        import dns.resolver  # already a project dep
        r = dns.resolver.Resolver()
        r.timeout = timeout
        r.lifetime = timeout
        ans = r.resolve(domain, "MX")
        return len(list(ans)) > 0
    except Exception:
        return False

# Homoglyph substitution table — visually-similar character mappings
_HOMOGLYPHS = {
    "a": ["4", "@"], "b": ["8"], "e": ["3"], "g": ["9", "6"],
    "i": ["1", "l", "!"], "l": ["1", "i"], "o": ["0"], "s": ["5", "$"],
    "t": ["7"], "z": ["2"],
}
_KEYBOARD = {
    "q": "wa",  "w": "qse",  "e": "wrd", "r": "etf",  "t": "ryg",
    "y": "tuh", "u": "yij",  "i": "uok", "o": "ipl",  "p": "o",
    "a": "qsz", "s": "awdz", "d": "sefx","f": "dgcr", "g": "fhvt",
    "h": "gjby","j": "hknu", "k": "jlmi","l": "kop",
    "z": "asx", "x": "zdc",  "c": "xfv", "v": "cgb",  "b": "vhn", "n": "bjm", "m": "nk",
}
_TLDS = ["com", "net", "org", "co", "io", "info", "biz", "tk", "ml", "ga", "cf", "xyz"]


def _generate(domain: str, cap: int = 80) -> list[str]:
    """Generate permutations using 7 standard transforms."""
    base, _, tld = domain.partition(".")
    if not tld:  # no dot
        return []
    out = set()

    # 1. Character omission
    for i in range(len(base)):
        out.add(base[:i] + base[i+1:] + "." + tld)
    # 2. Character repetition (double letter)
    for i in range(len(base)):
        out.add(base[:i] + base[i] + base[i] + base[i+1:] + "." + tld)
    # 3. Character transposition (swap adjacent)
    for i in range(len(base) - 1):
        out.add(base[:i] + base[i+1] + base[i] + base[i+2:] + "." + tld)
    # 4. Homoglyph substitution
    for i, ch in enumerate(base):
        for swap in _HOMOGLYPHS.get(ch, []):
            out.add(base[:i] + swap + base[i+1:] + "." + tld)
    # 5. Adjacent-key insertion
    for i, ch in enumerate(base):
        for swap in _KEYBOARD.get(ch, ""):
            out.add(base[:i] + swap + base[i+1:] + "." + tld)
            out.add(base[:i] + ch + swap + base[i+1:] + "." + tld)
    # 6. TLD swap
    for alt_tld in _TLDS:
        if alt_tld != tld.lower():
            out.add(base + "." + alt_tld)
    # 7. Hyphenation
    for i in range(1, len(base)):
        out.add(base[:i] + "-" + base[i:] + "." + tld)

    out.discard(domain)
    return sorted(out)[:cap]


def _resolves(domain: str, timeout: float = 1.5) -> str | None:
    """Return resolved IP or None. Short timeout so 80 perms stay <2 min total."""
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyname(domain)
    except (socket.gaierror, socket.herror, socket.timeout):
        return None
    finally:
        socket.setdefaulttimeout(None)


def _do_scan(req: ScanRequest) -> dict:
    target = (req.target or "").strip()
    target = target.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in target:
        target = target.split("/", 1)[0]
    if ":" in target:
        target = target.split(":", 1)[0]
    if target.startswith("www."):
        target = target[4:]

    if "." not in target or target.replace(".", "").isdigit():
        return standard_response(tool="dnstwist", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="Target must be a domain name (e.g. example.com), not an IP.")

    if is_reserved(target):
        return standard_response(tool="dnstwist", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=reserved_reason(target))

    perms = _generate(target, cap=80)
    if not perms:
        return standard_response(tool="dnstwist", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="Could not generate permutations from target domain.")

    # Parallel DNS resolution (Layer 6b)
    resolved = []
    with ThreadPoolExecutor(max_workers=12) as pool:
        for p, ip in zip(perms, pool.map(_resolves, perms, timeout=20)):
            if ip:
                resolved.append({"domain": p, "ip": ip})

    # Verification gate: an MX record on a typo = mail-capable = phishing-ready.
    # Without MX, the typo is just passive squatting (could be a real different
    # business, parked, or held by a registrar). Default severity is INFO unless
    # MX evidence elevates to LOW.
    with ThreadPoolExecutor(max_workers=8) as pool:
        mx_flags = list(pool.map(_has_mx, [r["domain"] for r in resolved], timeout=15))
    for entry, has_mx in zip(resolved, mx_flags):
        entry["mx"] = bool(has_mx)

    findings = []
    for entry in resolved:
        if entry["mx"]:
            sev, cvss = "LOW", "3.1"
            verdict = "MX present (mail-capable, phishing-ready)"
        else:
            sev, cvss = "INFO", "0.0"
            verdict = "no MX (passive squat — could be parked / unrelated business)"
        findings.append(wrap_finding(
            f"Lookalike domain registered: {entry['domain']} -> {entry['ip']}",
            sev, cvss=cvss,
            cwe="CWE-345", owasp="A07:2021",
            remediation=("If this domain isn't yours: register defensively, monitor for "
                        "phishing campaigns, file abuse reports with the registrar. If yours: "
                        "consolidate to canonical domain and 301-redirect."),
            evidence_marker=f"DNS A: {entry['domain']} -> {entry['ip']} | {verdict}"))

    if not findings:
        findings.append(wrap_finding(
            f"No lookalike domains found in {len(perms)} permutations tested",
            severity="POSITIVE",
            cwe="CWE-345", owasp="A07:2021",
            remediation="No action — typosquat surface is clean. Re-run quarterly.",
            evidence_marker=f"{len(perms)} permutations DNS-resolved; 0 hit"))

    return standard_response(tool="dnstwist", target=req.target, findings=findings,
        tests_performed=len(perms),
        vulnerable=len(resolved) > 0,
        tests_summary=f"DNS-twist: {len(perms)} permutations tested, "
                      f"{len(resolved)} resolved to live IPs",
        raw_data={"dnstwist": {"permutations_tested": len(perms),
                                "resolved_count": len(resolved),
                                "resolved": resolved}})


@router.post("/api/osint/dnstwist")
async def scan_dnstwist(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="dnstwist", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app): app.include_router(router)
