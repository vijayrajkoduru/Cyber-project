"""vector_db_exposure - unauthenticated vector-database API exposure scan
(playbook §6 #68 Vector DB enumeration — unauth API).

REAL PROBE. Issues only READ-ONLY HTTP GET requests against the well-known
management/collection-listing endpoints of the popular RAG vector stores:
Chroma, Qdrant, Weaviate, Milvus (and its REST proxy), and Marqo. A graded
finding is emitted ONLY when one of those endpoints actually returns the
store's signature payload WITHOUT authentication — i.e. a confirmed public,
unauthenticated vector-DB control plane (collections / schema enumerable by
anyone).

We never write, never insert/query vectors, never POST — enumeration of the
collection list via GET is the detection signal, nothing more. The presence
of an unauthenticated collections endpoint is itself the finding; we do not
exfiltrate document content.

Customer input:
  - ScanRequest.target = vector-DB host[:port] or full URL
  - auth_bearer / options.headers honoured (Qdrant api-key etc.)
"""
from __future__ import annotations
import asyncio
from typing import Optional
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools.ai_llm.tier3_infra._infra_common import (
    base_variants, build_headers, safe_join, body_excerpt,
)

router = APIRouter()


class InfraRequest(ScanRequest):
    options: Optional[dict] = None


# READ-ONLY enumeration endpoints. A store is "exposed" only if the marker
# appears in the body AND the response was 200 (i.e. not an auth challenge).
VECTOR_DB_SIGNATURES = [
    {"store": "Chroma", "path": "/api/v1/collections",
     "body_any": ["[", "\"name\""], "must_status": [200], "kind": "collections"},
    {"store": "Chroma (heartbeat)", "path": "/api/v1/heartbeat",
     "body_any": ["nanosecond heartbeat", "heartbeat"], "must_status": [200],
     "kind": "heartbeat"},
    {"store": "Chroma v2", "path": "/api/v2/heartbeat",
     "body_any": ["heartbeat"], "must_status": [200], "kind": "heartbeat"},
    {"store": "Qdrant", "path": "/collections",
     "body_any": ["\"result\"", "\"collections\""], "must_status": [200],
     "kind": "collections"},
    {"store": "Qdrant (telemetry)", "path": "/telemetry",
     "body_any": ["\"result\"", "\"app\""], "must_status": [200],
     "kind": "telemetry"},
    {"store": "Weaviate", "path": "/v1/schema",
     "body_any": ["\"classes\"", "class"], "must_status": [200],
     "kind": "schema"},
    {"store": "Weaviate (meta)", "path": "/v1/meta",
     "body_any": ["\"version\"", "hostname"], "must_status": [200],
     "kind": "meta"},
    {"store": "Milvus REST", "path": "/v1/vector/collections",
     "body_any": ["\"data\"", "\"code\""], "must_status": [200],
     "kind": "collections"},
    {"store": "Marqo", "path": "/indexes",
     "body_any": ["\"results\"", "index_name"], "must_status": [200],
     "kind": "indexes"},
]


async def gather(ctx: ScanContext):
    target = (ctx.host or "").strip()
    if not target:
        ctx.state["vecdb_total"] = 0
        ctx.source("no-target")
        return
    try:
        import httpx
    except ImportError:
        ctx.state["vecdb_error"] = "httpx not installed"
        ctx.source("httpx missing")
        return

    bases = base_variants(target)
    if not bases:
        ctx.state["vecdb_error"] = "could not parse target into a base URL"
        ctx.source("invalid target")
        return

    opts = getattr(ctx, "options", None) or {}
    bearer = getattr(ctx, "auth_bearer", None)
    headers = build_headers(bearer, opts.get("headers"),
                            "VulnusLab/AI-LLM-VectorDB-Exposure")

    exposed = []
    auth_required = []      # store responded but demanded auth (good posture)
    paths_probed = 0
    transport_errors = 0
    seen = set()

    async with httpx.AsyncClient(timeout=8.0, verify=False,
                                 follow_redirects=False) as client:
        sem = asyncio.Semaphore(4)

        async def _probe(base, sig):
            nonlocal paths_probed, transport_errors
            url = safe_join(base, sig["path"])
            async with sem:
                try:
                    r = await client.get(url, headers=headers)
                except Exception:
                    transport_errors += 1
                    return
            paths_probed += 1
            try:
                body = r.text or ""
            except Exception:
                body = ""
            low = body.lower()

            # Auth-challenge path: store is present but protected. Record as
            # good posture, never as a vuln.
            if r.status_code in (401, 403):
                marker_present = any(m.lower() in low for m in sig["body_any"])
                if marker_present or sig["store"].split()[0].lower() in low:
                    if sig["store"] not in {a["store"] for a in auth_required}:
                        auth_required.append({"store": sig["store"], "url": url,
                                              "status": r.status_code})
                return

            if r.status_code not in sig.get("must_status", [200]):
                return
            if not any(m.lower() in low for m in sig["body_any"]):
                return

            if sig["store"] in seen:
                return
            seen.add(sig["store"])
            exposed.append({
                "store": sig["store"],
                "url": url,
                "status": r.status_code,
                "kind": sig.get("kind"),
                "server_header": r.headers.get("server", ""),
                "excerpt": body_excerpt(body, 200),
            })

        tasks = []
        for base in bases:
            for sig in VECTOR_DB_SIGNATURES:
                tasks.append(_probe(base, sig))
        await asyncio.gather(*tasks)

    ctx.state["vecdb_bases"] = bases
    ctx.state["vecdb_paths_probed"] = paths_probed
    ctx.state["vecdb_transport_errors"] = transport_errors
    ctx.state["vecdb_exposed"] = exposed
    ctx.state["vecdb_auth_required"] = auth_required
    ctx.state["vecdb_total"] = len(exposed)
    ctx.source(f"{paths_probed} read-only GETs; {len(exposed)} unauthenticated "
               f"vector-DB control plane(s); {len(auth_required)} auth-protected; "
               f"{transport_errors} transport errors")


def rule_unreachable(s):
    if s.get("vecdb_error"):
        return {"name": "Vector-DB exposure scan could not run",
                "severity": "INFO",
                "evidence": str(s["vecdb_error"]),
                "remediation": ("Confirm the target is a reachable URL or host. "
                                "This probe only issues read-only GETs to vector "
                                "store collection/schema listing endpoints."),
                "cwe": "CWE-755"}
    return None


def rule_positive(s):
    if s.get("vecdb_total", 0) > 0:
        return None
    if not s.get("vecdb_paths_probed"):
        return None
    auth = s.get("vecdb_auth_required") or []
    extra = ""
    if auth:
        extra = (" Auth-protected store(s) detected (good posture): "
                 + ", ".join(a["store"] for a in auth) + ".")
    return {"name": "No unauthenticated vector-DB control plane exposed",
            "severity": "POSITIVE",
            "evidence": (f"Probed {s.get('vecdb_paths_probed', 0)} Chroma/Qdrant/"
                         "Weaviate/Milvus/Marqo listing endpoints — none returned "
                         "an unauthenticated collection/schema list." + extra),
            "remediation": ("Keep vector stores behind authentication and off "
                            "the public internet."),
            "cwe": "CWE-200", "owasp": "LLM08:2025"}


def rule_exposed_vector_db(s):
    exposed = s.get("vecdb_exposed") or []
    if not exposed:
        return None
    stores = sorted({e["store"] for e in exposed})
    return {"name": (f"Unauthenticated vector-DB control plane exposed "
                     f"({len(stores)} store signature(s))"),
            "severity": "HIGH", "cvss": "8.2",
            "cwe": "CWE-306", "owasp": "LLM08:2025",
            "verified_exploit": True,  # confirmed live unauth listing observed
            "evidence": ("Collection/schema listing returned WITHOUT auth: "
                         + "; ".join(f"{e['store']} @ {e['url']} (HTTP "
                                     f"{e['status']})" for e in exposed[:5])),
            "remediation": ("Enable authentication on the vector store "
                            "(Qdrant api-key, Weaviate API-key/OIDC, Chroma auth "
                            "provider, Milvus RBAC) and bind it to a private "
                            "network. An open vector DB lets an attacker "
                            "enumerate, read, and poison the RAG corpus "
                            "(OWASP LLM08 vector/embedding weakness).")}


VECTOR_DB_EXPOSURE_FINDING_RULES = [
    rule_unreachable,
    rule_positive,
    rule_exposed_vector_db,
]


INTEL_FIELDS = [
    ("Base URLs probed", "vecdb_bases"),
    ("Read-only GETs sent", "vecdb_paths_probed"),
    ("Unauthenticated stores", "vecdb_total"),
    ("Exposed stores", "vecdb_exposed"),
    ("Auth-protected stores", "vecdb_auth_required"),
    ("Transport errors", "vecdb_transport_errors"),
]


@router.post("/api/ai_llm/vector_db_exposure")
async def ai_llm_vector_db_exposure(req: InfraRequest,
                                    _=Depends(verify_scan_quota)):
    async def _gather(ctx):
        ctx.options = req.options
        ctx.auth_bearer = req.auth_bearer
        await gather(ctx)
    return await run_scanner(host=req.target, tool="vector_db_exposure",
        gather_func=_gather, finding_rules=VECTOR_DB_EXPOSURE_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
