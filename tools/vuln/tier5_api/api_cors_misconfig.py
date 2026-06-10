"""API CORS misconfiguration - MethodologyScanner refactor.

VL-METHOD Wave 6: probe CORS headers for origin reflection / null / wildcard
with credentials. 6 stages:
  pre_flight    - target reachable
  fingerprint   - SPA detection (informational only — CORS is real either way)
  quick_probe   - 2 fast probes (evil origin + null origin)
  deep_scan     - 4 more origin variants (subdomain, file:// origin, etc.)
                  only if quick found a misconfig
  verify        - replay the offending Origin with random nonce in path;
                  CONFIRMED only if response still echoes attacker origin
  privilege_check - CORS reflection = "guest" cross-origin read
"""
import ssl
import urllib.request
import asyncio
import secrets

from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url
from tools._vl_core.verify import vl_verify
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import detect_spa_catchall

router = APIRouter()

_EVIL_ORIGINS = [
    "https://evil.example.com",
    "https://attacker.test",
    "null",
    "https://evil-sub.test",  # subdomain variant
    "https://evil.example.com.legitimate.test",  # apex-confusion variant
    "file://",  # rare but real
]
_QUICK_ORIGINS = ["https://evil.example.com", "null"]

_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE


def _cors(url, origin, timeout=8):
    req = urllib.request.Request(
        url, headers={"Origin": origin,
                       "User-Agent": "Mozilla/5.0 (VulnusLab Vuln)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as r:
            h = {k.lower(): v for k, v in r.headers.items()}
    except Exception as e:
        h = {k.lower(): v for k, v in e.headers.items()} if getattr(e, "headers", None) else {}
    return h.get("access-control-allow-origin"), h.get("access-control-allow-credentials")


def _classify(origin, acao, acac):
    """Return ('reflect' | 'wild_creds' | 'null' | None)."""
    if not acao:
        return None
    acao = str(acao)
    if origin in acao and origin not in ("*",):
        return "reflect"
    if acao == "*" and str(acac).lower() == "true":
        return "wild_creds"
    if origin == "null" and acao == "null":
        return "null"
    return None


class ApiCorsMisconfig(MethodologyScanner):
    name = "api_cors_misconfig"

    async def pre_flight(self, ctx):
        ctx.state["base_url"] = web_url(str(ctx.host)).rstrip("/")
        ctx.source("http")
        ctx.state["tested"] = 1
        return True

    async def fingerprint(self, ctx):
        spa = await detect_spa_catchall(ctx.state["base_url"])
        ctx.state["fingerprint"] = {
            "is_spa": spa.get("is_spa", False),
        }

    async def _probe_origins(self, ctx, origins):
        base = ctx.state["base_url"] + "/"
        misconfigs = []
        for origin in origins:
            acao, acac = await asyncio.to_thread(_cors, base, origin)
            kind = _classify(origin, acao, acac)
            if kind:
                misconfigs.append({"origin": origin, "acao": acao,
                                    "acac": acac, "kind": kind})
        return misconfigs

    async def quick_probe(self, ctx):
        hits = await self._probe_origins(ctx, _QUICK_ORIGINS)
        ctx.state["_quick_hits"] = hits
        return hits

    async def deep_scan(self, ctx):
        deep_origins = [o for o in _EVIL_ORIGINS if o not in _QUICK_ORIGINS]
        hits = await self._probe_origins(ctx, deep_origins)
        ctx.state["_deep_hits"] = hits
        return hits

    async def verify(self, ctx, finding):
        # Replay with the same Origin but a cache-busting URL path. If the
        # ACAO header still reflects the attacker, it's not a cached
        # response — it's a real reflection bug.
        base = ctx.state["base_url"] + f"/?vl_verify={secrets.token_hex(6)}"
        acao, acac = await asyncio.to_thread(_cors, base, finding["origin"])
        kind = _classify(finding["origin"], acao, acac)
        if kind == finding.get("kind"):
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = (
                f"cache-bust replay still reflects Origin '{finding['origin']}'")
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = (
                f"replay returned ACAO={acao}, ACAC={acac} (kind={kind})")
        return finding

    async def privilege_check(self, ctx, finding):
        finding["privilege_level"] = "guest" if finding.get("confidence") == "CONFIRMED" else "unknown"
        return finding


def _r_reflect(s):
    verified = s.get("methodology_findings") or []
    confirmed = [f for f in verified if f.get("confidence") == "CONFIRMED"
                  and f.get("kind") == "reflect"]
    if not confirmed:
        return None
    creds_findings = [f for f in confirmed if str(f.get("acac")).lower() == "true"]
    if creds_findings:
        sev, cvss = "HIGH", 7.5
    else:
        sev, cvss = "MEDIUM", 5.3
    return {"name": f"CORS reflects arbitrary Origin ({len(confirmed)} variant(s)) (CONFIRMED)",
            "severity": sev, "cvss": cvss, "cwe": "CWE-942",
            "evidence": "; ".join(f"Origin '{f['origin']}' -> ACAO {f['acao']} "
                                    f"(creds={f['acac']})" for f in confirmed),
            "remediation": "Use an explicit origin allow-list; never reflect Origin with Allow-Credentials:true."}


def _r_null(s):
    verified = s.get("methodology_findings") or []
    null_hits = [f for f in verified if f.get("kind") == "null"
                  and f.get("confidence") == "CONFIRMED"]
    if not null_hits:
        return None
    return {"name": "CORS allows 'null' origin (CONFIRMED)",
            "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-942",
            "evidence": "ACAO: null - exploitable from sandboxed iframes/data URIs",
            "remediation": "Do not allow the 'null' origin."}


def _r_wild(s):
    verified = s.get("methodology_findings") or []
    wild_hits = [f for f in verified if f.get("kind") == "wild_creds"
                  and f.get("confidence") == "CONFIRMED"]
    if not wild_hits:
        return None
    return {"name": "CORS wildcard with credentials (CONFIRMED)",
            "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-942",
            "evidence": "ACAO:* with Allow-Credentials:true",
            "remediation": "Never combine '*' with credentials."}


def _r_suspected(s):
    verified = s.get("methodology_findings") or []
    suspected = [f for f in verified if f.get("confidence") == "SUSPECTED"]
    if not suspected:
        return None
    return {"name": f"CORS misconfig possible ({len(suspected)} variant(s)) - SUSPECTED",
            "severity": "LOW", "cvss": 3.1, "cwe": "CWE-942",
            "evidence": "; ".join(f"Origin '{f['origin']}' kind={f.get('kind')}" for f in suspected),
            "remediation": "Manually verify CORS handling; cache-bust replay did not reproduce reflection."}


def _r_clean(s):
    verified = s.get("methodology_findings") or []
    if verified:
        return None
    if (s.get("tested") or 0) < 1:
        return None
    return {"name": "No CORS misconfiguration detected",
            "severity": "POSITIVE",
            "evidence": "ACAO did not reflect attacker/null/wildcard origins across probed variants."}


FINDING_RULES = [_r_reflect, _r_null, _r_wild, _r_suspected, _r_clean]
INTEL_FIELDS = [
    ("Stage timings (ms)", "stage_timings"),
    ("Verified findings", "methodology_findings"),
]


@router.post("/api/vuln/api_cors_misconfig")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = ApiCorsMisconfig()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
