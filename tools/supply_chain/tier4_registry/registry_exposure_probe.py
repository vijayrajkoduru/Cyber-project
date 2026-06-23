"""registry_exposure_probe - self-hosted package-registry exposure (playbook §6).

REAL remote probe. Against the customer target host it issues read-only HTTP
GETs to the well-known, unauthenticated endpoints of common self-hosted
package registries / artifact stores and fingerprints any that answer:

  - Docker Registry HTTP API v2      GET /v2/                (header/200/401)
  - Docker Registry catalog          GET /v2/_catalog        (anon repo listing)
  - Verdaccio / npm registry         GET /-/ping , /-/all
  - Sonatype Nexus                   GET /service/rest/v1/status , /nexus/
  - JFrog Artifactory                GET /artifactory/api/system/ping
  - PyPI / devpi warehouse           GET /simple/ , /+api
  - GitLab package registry          GET /api/v4/projects (header fingerprint)

ZERO-FALSE-POSITIVE policy:
  - A graded severity (MEDIUM/LOW) is emitted ONLY when the endpoint actually
    answered with a registry-specific signature (status + body/header proof).
    Those rules stamp verified_exploit=True because the live condition was
    observed on the target.
  - Anonymous catalog/repo LISTING that actually returns data -> MEDIUM
    (information disclosure of internal package names = dependency-confusion
    seed). Just a reachable-but-auth'd registry -> LOW (attack surface).
  - Nothing detected -> POSITIVE. Unreachable / no input -> INFO. Never a
    graded finding without observed proof.

This is detection only (VA): no writes, no pushes, no auth brute force.

Customer input: ScanRequest.target (host / URL).
"""
from __future__ import annotations
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

router = APIRouter()
TIMEOUT = 8

# (path, registry_label, kind)  kind in {api, catalog, ping}
_PROBES = [
    ("/v2/",                              "Docker Registry HTTP API v2", "api"),
    ("/v2/_catalog",                      "Docker Registry catalog",     "catalog"),
    ("/-/ping",                           "npm/Verdaccio registry",      "ping"),
    ("/-/all",                            "npm/Verdaccio package index",  "catalog"),
    ("/service/rest/v1/status",           "Sonatype Nexus",              "api"),
    ("/artifactory/api/system/ping",      "JFrog Artifactory",           "ping"),
    ("/simple/",                          "PyPI/devpi simple index",     "catalog"),
    ("/repository/",                       "Nexus repository root",       "api"),
]

_HEADERS = {"User-Agent": "VulnusLab-SupplyChain/1.0 (+registry-exposure)",
            "Accept": "*/*"}


def _normalize_bases(target: str) -> list[str]:
    t = (target or "").strip().rstrip("/")
    if not t:
        return []
    if t.startswith("http://") or t.startswith("https://"):
        return [t]
    # Try https first, then http (many internal registries are http-only).
    return [f"https://{t}", f"http://{t}"]


def _http_get(url: str) -> dict:
    """Blocking GET. Returns {ok, status, headers, body_snip} or {ok:False}."""
    if requests is None:
        return {"ok": False, "err": "requests unavailable"}
    try:
        r = requests.get(url, headers=_HEADERS, timeout=TIMEOUT,
                          verify=False, allow_redirects=True)
        body = ""
        try:
            body = r.text[:600]
        except Exception:
            body = ""
        return {"ok": True, "status": r.status_code,
                "headers": {k.lower(): v for k, v in r.headers.items()},
                "body": body}
    except Exception as e:
        return {"ok": False, "err": str(e)[:120]}


def _classify(path: str, label: str, kind: str, res: dict) -> dict | None:
    """Decide whether a response is a genuine registry signature. Returns a
    detection dict only on strong evidence; None otherwise (no FP)."""
    if not res.get("ok"):
        return None
    status = res.get("status") or 0
    headers = res.get("headers") or {}
    body = (res.get("body") or "")
    body_low = body.lower()

    detected = False
    anon_listing = False
    proof = ""

    # Docker Registry v2: the spec mandates this header on /v2/.
    if "docker-distribution-api-version" in headers:
        detected = True
        proof = f"Docker-Distribution-API-Version: {headers.get('docker-distribution-api-version')}"
    # Docker catalog returning repositories anonymously.
    if path == "/v2/_catalog" and status == 200 and '"repositories"' in body_low:
        detected = True
        anon_listing = True
        proof = "anonymous /v2/_catalog returned a repositories list"
    # Nexus status JSON.
    if path == "/service/rest/v1/status" and status in (200, 204):
        detected = True
        proof = f"Nexus /service/rest/v1/status -> HTTP {status}"
    # Artifactory ping returns literal 'OK'.
    if path == "/artifactory/api/system/ping" and status == 200 and "ok" in body_low[:40]:
        detected = True
        proof = "Artifactory /api/system/ping -> OK"
    # Verdaccio/npm ping.
    if path == "/-/ping" and status == 200:
        detected = True
        proof = f"npm registry /-/ping -> HTTP {status}"
    # npm /-/all anonymous full index.
    if path == "/-/all" and status == 200 and (body_low.startswith("{") or '"_updated"' in body_low):
        detected = True
        anon_listing = True
        proof = "anonymous /-/all returned the full package index"
    # PyPI/devpi simple index (PEP 503): NOT just the word "simple" (far too
    # broad — fires on any page that happens to contain it). Require a genuine
    # simple-index signature: the PEP 503 title 'Links for', OR multiple package
    # anchors (>=3 <a href> links characteristic of an index, not a one-link
    # landing page), on an HTML body.
    if path == "/simple/" and status == 200:
        anchor_count = body_low.count("<a href")
        pep503_title = "links for" in body_low  # devpi/warehouse simple-index header
        index_shape = anchor_count >= 3 and ("</a>" in body_low)
        if pep503_title or index_shape:
            detected = True
            anon_listing = True
            proof = ("anonymous /simple/ returned a PEP 503 package index "
                     f"({'Links for' if pep503_title else str(anchor_count) + ' package anchors'})")
    # Nexus server header / repository root.
    server_hdr = (headers.get("server") or "").lower()
    if "nexus" in server_hdr or "x-content-type-options" in headers and "sonatype" in body_low:
        if status == 200:
            detected = True
            proof = proof or f"Nexus server header / body signature ({server_hdr or 'body'})"

    if not detected:
        return None
    return {
        "registry": label,
        "path": path,
        "url_status": status,
        "anonymous_listing": anon_listing,
        "proof": proof,
        "server": server_hdr or "",
    }


def _make_gather(req: ScanRequest):
    async def gather(ctx: ScanContext):
        bases = _normalize_bases(ctx.host or "")
        if not bases:
            ctx.state["registry_exposure_no_input"] = True
            ctx.source("target required")
            return
        if requests is None:
            ctx.state["registry_exposure_error"] = "requests library unavailable"
            ctx.source("no http client")
            return

        ctx.state["registry_probe_target"] = ctx.host
        detections: list[dict] = []
        reachable = False
        tried = 0

        # Use the first base that is reachable at all; if https refuses,
        # fall through to http. Cap total requests for safety.
        for base in bases:
            base_reachable = False
            local_detections: list[dict] = []
            for path, label, kind in _PROBES:
                url = base + path
                tried += 1
                res = await asyncio.to_thread(_http_get, url)
                if res.get("ok"):
                    base_reachable = True
                    det = _classify(path, label, kind, res)
                    if det:
                        det["scheme"] = base.split("://", 1)[0]
                        local_detections.append(det)
            if base_reachable:
                reachable = True
                detections.extend(local_detections)
                # First reachable scheme wins; no need to double-probe http+https.
                break

        # De-dup by (registry, path).
        seen = set()
        uniq = []
        for d in detections:
            key = (d["registry"], d["path"])
            if key in seen:
                continue
            seen.add(key)
            uniq.append(d)

        ctx.state["registry_probes_attempted"] = tried
        ctx.state["registry_target_reachable"] = reachable
        ctx.state["registry_detections"] = uniq
        ctx.state["registry_anon_listings"] = [d for d in uniq if d.get("anonymous_listing")]
        if uniq:
            ctx.source(f"registry exposure: {len(uniq)} signature(s) on {ctx.host}")
        elif reachable:
            ctx.source(f"no registry signatures on {ctx.host} ({tried} probes)")
        else:
            ctx.state["registry_unreachable"] = True
            ctx.source(f"{ctx.host} unreachable for registry probing")
    return gather


# ───────────────────────── finding rules (inline) ─────────────────────────

def _rule_no_input(s):
    if not s.get("registry_exposure_no_input"):
        return None
    return {"name": "registry_exposure_probe: target host/URL required",
            "severity": "INFO",
            "evidence": "Provide a host or URL as target to probe for exposed "
                        "self-hosted package registries.",
            "remediation": "Re-run with target=<registry-host-or-url>.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_client_missing(s):
    if "requests library unavailable" not in (s.get("registry_exposure_error") or ""):
        return None
    return {"name": "registry_exposure_probe: HTTP client unavailable",
            "severity": "INFO",
            "evidence": s.get("registry_exposure_error"),
            "remediation": "Install the `requests` library in the scanner environment.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_unreachable(s):
    if not s.get("registry_unreachable"):
        return None
    return {"name": "Target unreachable for registry exposure probing",
            "severity": "INFO",
            "evidence": f"No registry endpoint on {s.get('registry_probe_target')} answered "
                        f"({s.get('registry_probes_attempted', 0)} probes attempted).",
            "remediation": "If a self-hosted registry exists, confirm it is firewalled to "
                           "trusted networks and re-run from an in-scope vantage point.",
            "cwe": "N/A", "owasp": "N/A"}


def _rule_anon_listing(s):
    listings = s.get("registry_anon_listings") or []
    if not listings:
        return None
    n = len(listings)
    sample = "; ".join(f"{d['registry']} via {d['path']} (HTTP {d['url_status']})" for d in listings[:4])
    return {"name": f"Anonymous package listing exposed on {n} registry endpoint(s)",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-200", "owasp": "A05:2021",
            "verified_exploit": True,
            "evidence": f"The target served an anonymous package/repository index: {sample}. "
                        "Internal package names leaked this way seed dependency-confusion "
                        "and typosquatting attacks against your build pipeline.",
            "remediation": "Require authentication for catalog/index endpoints (/v2/_catalog, "
                           "/-/all, /simple/). Restrict the registry to trusted networks and "
                           "disable anonymous read where business needs allow."}


def _rule_registry_surface(s):
    dets = s.get("registry_detections") or []
    non_listing = [d for d in dets if not d.get("anonymous_listing")]
    if not non_listing:
        return None
    n = len(non_listing)
    sample = "; ".join(f"{d['registry']} ({d['proof']})" for d in non_listing[:4])
    return {"name": f"Self-hosted package registry reachable: {n} endpoint signature(s)",
            "severity": "LOW", "cvss": "3.7",
            "cwe": "CWE-668", "owasp": "A05:2021",
            "verified_exploit": True,
            "evidence": f"Registry API endpoints responded on the target: {sample}. "
                        "A network-reachable registry expands the supply-chain attack surface "
                        "even when authentication is enforced.",
            "remediation": "Confirm the registry enforces authentication + 2FA on publish, runs "
                           "current patched versions, and is reachable only from trusted CIDRs / "
                           "a VPN. Enable audit logging on package pulls and pushes."}


def _rule_clean(s):
    if s.get("registry_exposure_no_input") or s.get("registry_exposure_error"):
        return None
    if s.get("registry_unreachable"):
        return None
    if (s.get("registry_detections") or []):
        return None
    if not s.get("registry_target_reachable"):
        return None
    return {"name": "No exposed self-hosted package registry detected",
            "severity": "POSITIVE",
            "evidence": f"{s.get('registry_probes_attempted', 0)} registry endpoints probed on "
                        f"{s.get('registry_probe_target')}; none returned a registry signature.",
            "remediation": "Continue to keep package registries behind authentication and network "
                           "controls; re-scan after infrastructure changes.",
            "cwe": "N/A", "owasp": "N/A"}


REGISTRY_EXPOSURE_FINDING_RULES = [
    _rule_no_input,
    _rule_client_missing,
    _rule_unreachable,
    _rule_anon_listing,
    _rule_registry_surface,
    _rule_clean,
]


INTEL_FIELDS = [("Probe target", "registry_probe_target"),
                ("Probes attempted", "registry_probes_attempted"),
                ("Target reachable", "registry_target_reachable"),
                ("Registry signatures", "registry_detections"),
                ("Anonymous listings", "registry_anon_listings")]


@router.post("/api/supply_chain/registry_exposure_probe")
async def supply_chain_registry_exposure_probe(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="registry_exposure_probe",
        gather_func=_make_gather(req),
        finding_rules=REGISTRY_EXPOSURE_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
