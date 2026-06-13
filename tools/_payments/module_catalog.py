"""Per-module sales catalogue — à la carte monthly pricing.

Each entry's KEY is the canonical module id, which MUST match:
  - the backend module dir  (tools/<id>/ and /api/<id>/run_all), and
  - the frontend MODULES catalog id (src/App.js),
so that an entitlement check, a scan route, and the dashboard tile all agree.

Customers subscribe to individual modules (monthly). amount is in PAISE (INR*100)
and is a PLACEHOLDER — set your real prices before going live. period_days=30.
"""
from __future__ import annotations

MODULE_PERIOD_DAYS = 30

# id -> {label, amount (paise/month), blurb}
MODULE_CATALOG = {
    "recon":         {"label": "Reconnaissance & OSINT",   "amount": 99900,  "blurb": "Attack-surface mapping, subdomains, DNS, WHOIS, leaks."},
    "vuln":          {"label": "Vulnerability Scanning",    "amount": 149900, "blurb": "Service/CVE + image CVE (Trivy), KEV/EPSS-ranked."},
    "webapp":        {"label": "Web Application Pentest",   "amount": 199900, "blurb": "OWASP Top 10 — injection, XSS, auth, headers, JWT."},
    "supply_chain":  {"label": "Supply Chain Security",     "amount": 149900, "blurb": "SCA, SBOM, secrets, dependency confusion, typosquats."},
    "container_k8s": {"label": "Container & Kubernetes",    "amount": 149900, "blurb": "Image CVEs, Dockerfile, pod-spec, kubeconfig, RBAC."},
    "cloud":         {"label": "Cloud Security",            "amount": 199900, "blurb": "Cloud posture + IaC (tfsec/checkov) misconfigurations."},
    "apisec":        {"label": "API Security",              "amount": 149900, "blurb": "OpenAPI/Swagger, auth, CORS, versioning, exposure."},
    "password":      {"label": "Password Attacks",          "amount": 99900,  "blurb": "Spray/brute (Hydra/Medusa/Ncrack) + John hash audit."},
    "ad":            {"label": "Active Directory",          "amount": 149900, "blurb": "Kerberoast, AS-REP, ADCS, SMB spray, enumeration."},
    "wireless":      {"label": "Wireless Security",         "amount": 99900,  "blurb": "Wi-Fi/WPA, Bluetooth, WPS, management-plane TLS."},
    "phishing":      {"label": "Phishing & Social Eng",     "amount": 99900,  "blurb": "SPF/DKIM/DMARC, lookalikes, MTA-STS, landing checks."},
    "ai_llm":        {"label": "AI / LLM Security",         "amount": 149900, "blurb": "OWASP LLM Top 10 — prompt injection, PII, jailbreak."},
}
# TODO(pricing): replace the amounts above with your confirmed INR prices.


def get_module(module_id):
    return MODULE_CATALOG.get((module_id or "").strip())


def price_for(module_ids) -> int:
    """Total monthly amount (paise) for a list of module ids. Unknown ids cost 0."""
    total = 0
    for mid in module_ids or []:
        m = MODULE_CATALOG.get((mid or "").strip())
        if m:
            total += int(m["amount"])
    return total


def valid_ids(module_ids):
    """Filter to known, de-duplicated module ids (preserves order)."""
    seen, out = set(), []
    for mid in module_ids or []:
        mid = (mid or "").strip()
        if mid in MODULE_CATALOG and mid not in seen:
            seen.add(mid)
            out.append(mid)
    return out


def public_modules():
    """Catalogue for the checkout page."""
    return [
        {"id": mid, "label": m["label"], "amount": m["amount"], "blurb": m["blurb"]}
        for mid, m in MODULE_CATALOG.items()
    ]
