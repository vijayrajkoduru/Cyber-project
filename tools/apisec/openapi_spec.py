"""OpenAPI 3.x / Swagger 2.0 spec -> concrete, testable API endpoints.

Used by the API security pack (tools/apisec/apisec_pack.py) to turn the spec a
customer stored on their target profile (PUT /api/profiles/{id}/openapi) into
the list of operations the scanner exercises, instead of relying only on
crawling / path guessing.

Pure stdlib (+ optional PyYAML, which is in requirements.txt). Never raises on
a bad spec: parse_spec() returns (None, "reason") and build_operations() skips
anything malformed.
"""
import json
import re
from urllib.parse import quote, urlsplit

HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
MAX_OPERATIONS = 1000          # parsed (inventory); probing is capped separately
_MAX_REF_DEPTH = 15
_MAX_SCHEMA_DEPTH = 6
_PATH_PARAM_RE = re.compile(r"\{([^{}/]+)\}")


# ── Load / detect ─────────────────────────────────────────────────
def parse_spec(text):
    """Parse spec text (JSON or YAML). Returns (doc, kind, error):
    kind is "openapi3" | "swagger2"; on failure doc/kind are None."""
    if not isinstance(text, str) or not text.strip():
        return None, None, "empty spec"
    doc = None
    try:
        doc = json.loads(text)
    except Exception:
        try:
            import yaml  # PyYAML (requirements.txt)
            doc = yaml.safe_load(text)
        except ImportError:
            return None, None, "spec is not JSON and PyYAML is unavailable for YAML"
        except Exception as e:
            return None, None, f"spec is neither valid JSON nor YAML ({type(e).__name__})"
    if not isinstance(doc, dict):
        return None, None, "spec root is not an object"
    oa = str(doc.get("openapi") or "")
    sw = str(doc.get("swagger") or "")
    if oa.startswith("3"):
        kind = "openapi3"
    elif sw.startswith("2"):
        kind = "swagger2"
    elif oa or sw:
        return None, None, f"unsupported spec version {(oa or sw)[:20]!r} (need OpenAPI 3.x or Swagger 2.0)"
    else:
        return None, None, "document has no openapi/swagger version key"
    if not isinstance(doc.get("paths"), dict):
        return None, None, "spec has no 'paths' object"
    return doc, kind, None


# ── $ref resolution (local refs only; remote refs are never fetched) ──
def _resolve(doc, node, depth=0):
    seen = 0
    while isinstance(node, dict) and isinstance(node.get("$ref"), str):
        ref = node["$ref"]
        if not ref.startswith("#/") or depth + seen > _MAX_REF_DEPTH:
            return {}
        cur = doc
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(cur, dict) or part not in cur:
                return {}
            cur = cur[part]
        node = cur
        seen += 1
    return node if isinstance(node, dict) else {}


# ── Example / placeholder values ───────────────────────────────────
def _string_placeholder(fmt, name=""):
    fmt = (fmt or "").lower()
    n = (name or "").lower()
    if fmt == "uuid" or n.endswith("uuid") or n == "guid":
        return "00000000-0000-4000-8000-000000000001"
    if fmt == "date":
        return "2024-01-01"
    if fmt == "date-time":
        return "2024-01-01T00:00:00Z"
    if fmt == "email" or "email" in n:
        return "test@example.com"
    if fmt in ("uri", "url") or n.endswith("url"):
        return "https://example.com/"
    if fmt in ("ipv4", "ip"):
        return "192.0.2.1"
    if fmt == "byte":
        return "dGVzdA=="
    if n.endswith("id") or n == "id":
        return "1"
    return "test"


def example_from_schema(doc, schema, name="", depth=0, seen=frozenset()):
    """Best-effort example value for a JSON schema (example > default > enum
    > type-based placeholder). Bounded recursion; cycles collapse to None."""
    if depth > _MAX_SCHEMA_DEPTH:
        return None
    ref = schema.get("$ref") if isinstance(schema, dict) else None
    if isinstance(ref, str):
        if ref in seen:          # recursive schema (Pet.owner.pets[] -> Pet)
            return None
        seen = seen | {ref}
    s = _resolve(doc, schema, depth)
    if not s:
        return "test"
    for k in ("example", "default", "const"):
        if k in s and s[k] is not None:
            return s[k]
    if isinstance(s.get("examples"), list) and s["examples"]:
        return s["examples"][0]
    if isinstance(s.get("enum"), list) and s["enum"]:
        return s["enum"][0]
    for comb in ("allOf", "oneOf", "anyOf"):
        if isinstance(s.get(comb), list) and s[comb]:
            if comb == "allOf":
                merged = {}
                for sub in s[comb]:
                    v = example_from_schema(doc, sub, name, depth + 1, seen)
                    if isinstance(v, dict):
                        merged.update(v)
                if merged:
                    return merged
            return example_from_schema(doc, s[comb][0], name, depth + 1, seen)
    t = s.get("type")
    if isinstance(t, list):
        t = next((x for x in t if x != "null"), "string")
    if t is None and isinstance(s.get("properties"), dict):
        t = "object"
    if t == "integer":
        mn = s.get("minimum")
        return int(mn) if isinstance(mn, (int, float)) and mn > 1 else 1
    if t == "number":
        mn = s.get("minimum")
        return float(mn) if isinstance(mn, (int, float)) and mn > 1 else 1.0
    if t == "boolean":
        return True
    if t == "array":
        item = example_from_schema(doc, s.get("items") or {}, name, depth + 1, seen)
        return [item] if item is not None else []
    if t == "object":
        out = {}
        props = s.get("properties") if isinstance(s.get("properties"), dict) else {}
        for pname, psch in list(props.items())[:40]:
            if _resolve(doc, psch, depth).get("readOnly"):
                continue
            v = example_from_schema(doc, psch, pname, depth + 1, seen)
            if v is not None:
                out[pname] = v
        return out
    return _string_placeholder(s.get("format"), name)


def _param_value(doc, p, kind):
    if "example" in p and p["example"] is not None:
        return p["example"]
    ex = p.get("examples")
    if isinstance(ex, dict) and ex:
        first = _resolve(doc, next(iter(ex.values())))
        if "value" in first:
            return first["value"]
    if kind == "openapi3":
        sch = p.get("schema")
        if sch is None and isinstance(p.get("content"), dict) and p["content"]:
            sch = (next(iter(p["content"].values())) or {}).get("schema")
        return example_from_schema(doc, sch or {"type": "string"}, p.get("name", ""))
    # Swagger 2.0 non-body params carry the schema inline (type/format/enum...)
    inline = {k: p[k] for k in ("type", "format", "enum", "default", "items", "minimum")
              if k in p}
    return example_from_schema(doc, inline or {"type": "string"}, p.get("name", ""))


def _scalar(v):
    if isinstance(v, list):
        v = v[0] if v else ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (dict, list)):
        return json.dumps(v, separators=(",", ":"))
    return "" if v is None else str(v)


# ── Servers / base URL ─────────────────────────────────────────────
def spec_servers(doc, kind):
    """Server URLs declared by the spec, variables substituted. May be
    relative ("/api/v1") or absolute."""
    out = []
    if kind == "openapi3":
        for s in (doc.get("servers") or [])[:10]:
            if not isinstance(s, dict) or not isinstance(s.get("url"), str):
                continue
            url = s["url"].strip()
            vars_ = s.get("variables") if isinstance(s.get("variables"), dict) else {}

            def _sub(m, vars_=vars_):
                v = vars_.get(m.group(1)) or {}
                d = v.get("default")
                if d is None and isinstance(v.get("enum"), list) and v["enum"]:
                    d = v["enum"][0]
                return str(d) if d is not None else ""
            out.append(_PATH_PARAM_RE.sub(_sub, url))
    else:
        base_path = doc.get("basePath") if isinstance(doc.get("basePath"), str) else ""
        host = doc.get("host") if isinstance(doc.get("host"), str) else ""
        schemes = [x for x in (doc.get("schemes") or []) if x in ("http", "https")]
        if host:
            for sc in (schemes or ["https"])[:2]:
                out.append(f"{sc}://{host}{base_path}")
        else:
            out.append(base_path or "")
    return [u for u in out if u is not None] or [""]


def resolve_base(doc, kind, target_base, server_allowed=None):
    """Pick the base URL to test the spec against.

    * absolute server on the scan target's host           -> used as-is
    * absolute server on another host, and server_allowed(url) is True
      (i.e. that host is in the customer's profile scope)  -> used as-is
    * absolute server on another (out-of-scope) host       -> its PATH is
      re-rooted onto the scan target (we never leave scope)
    * relative server ("/v1", "v1")                       -> joined onto target
    Returns (base_url, note)."""
    t = urlsplit(target_base if "://" in target_base else "https://" + target_base)
    origin = f"{t.scheme}://{t.netloc}"
    tpath = (t.path or "").rstrip("/")
    servers = spec_servers(doc, kind)
    first = servers[0] if servers else ""
    if first.startswith("//"):
        first = f"{t.scheme}:{first}"
    if "://" in first:
        s = urlsplit(first)
        if (s.hostname or "").lower() == (t.hostname or "").lower() and s.hostname:
            return first.rstrip("/"), "spec server matches scan target"
        if server_allowed is not None and s.hostname:
            try:
                if server_allowed(first):
                    return first.rstrip("/"), f"spec server {s.netloc} is in profile scope"
            except Exception:
                pass
        return (origin + (s.path or "").rstrip("/")), \
            f"spec server {s.netloc or first[:80]} not the scan target/in scope - path re-rooted onto target"
    if first.startswith("/"):
        return origin + first.rstrip("/"), "relative spec server joined onto target origin"
    if first:
        return f"{origin}{tpath}/{first.strip('/')}".rstrip("/"), "relative spec server joined onto target"
    return origin + tpath, "no servers in spec - using scan target"


# ── Operations ─────────────────────────────────────────────────────
def build_operations(doc, kind):
    """Flatten the spec into concrete operations:
    {method, path (template), filled_path, query{}, headers{}, body, content_type,
     requires_auth, operation_id, deprecated}."""
    ops = []
    global_sec = doc.get("security")
    for path, item in list(doc.get("paths", {}).items()):
        if len(ops) >= MAX_OPERATIONS:
            break
        if not isinstance(path, str) or not path.startswith("/"):
            continue
        item = _resolve(doc, item)
        if not item:
            continue
        common = [x for x in (item.get("parameters") or []) if isinstance(x, dict)]
        for m in HTTP_METHODS:
            op = item.get(m)
            if not isinstance(op, dict):
                continue
            try:
                ops.append(_operation(doc, kind, path, m, op, common, global_sec))
            except Exception:
                continue  # malformed operation - skip it, keep the rest
            if len(ops) >= MAX_OPERATIONS:
                break
    return ops


def _operation(doc, kind, path, method, op, common, global_sec):
    params = {}
    for raw in list(common) + [x for x in (op.get("parameters") or []) if isinstance(x, dict)]:
        p = _resolve(doc, raw)
        if p.get("name") and p.get("in"):
            params[(p["name"], p["in"])] = p
    path_vals, query, headers, form = {}, {}, {}, {}
    body, ctype = None, None
    for (name, loc), p in params.items():
        if loc == "body":                         # Swagger 2.0 body param
            body = example_from_schema(doc, p.get("schema") or {}, name)
            ctype = "application/json"
            continue
        val = _param_value(doc, p, kind)
        if loc == "path":
            path_vals[name] = _scalar(val) or "1"
        elif loc == "query" and (p.get("required") or "example" in p or "default" in p
                                 or "enum" in p or "example" in (p.get("schema") or {})):
            query[name] = _scalar(val)
        elif loc == "header" and p.get("required") and name.lower() not in (
                "authorization", "cookie", "host", "content-length"):
            headers[name] = _scalar(val)
        elif loc == "formData":
            form[name] = _scalar(val)
    if form and body is None:
        body = form
        consumes = op.get("consumes") or doc.get("consumes") or []
        ctype = "multipart/form-data" if "multipart/form-data" in consumes \
            else "application/x-www-form-urlencoded"
    if kind == "openapi3" and isinstance(op.get("requestBody"), dict):
        rb = _resolve(doc, op["requestBody"])
        content = rb.get("content") if isinstance(rb.get("content"), dict) else {}
        pick = next((c for c in content if "json" in c.lower()), None) or \
            next((c for c in content if "form" in c.lower()), None) or \
            next(iter(content), None)
        if pick:
            media = content.get(pick) or {}
            if "example" in media:
                body = media["example"]
            elif isinstance(media.get("examples"), dict) and media["examples"]:
                body = _resolve(doc, next(iter(media["examples"].values()))).get("value")
            else:
                body = example_from_schema(doc, media.get("schema") or {}, "")
            ctype = pick
    # Fill path params (also ones the spec forgot to declare).
    filled = _PATH_PARAM_RE.sub(
        lambda mm: quote(path_vals.get(mm.group(1), "1"), safe=""), path)
    sec = op.get("security", global_sec)
    requires_auth = isinstance(sec, list) and bool(sec) and all(bool(r) for r in sec)
    return {
        "method": method.upper(),
        "path": path,
        "filled_path": filled,
        "query": query,
        "headers": headers,
        "body": body,
        "content_type": ctype,
        "requires_auth": requires_auth,
        "operation_id": str(op.get("operationId") or "")[:120],
        "deprecated": bool(op.get("deprecated")),
    }


def summarize(doc, kind):
    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    return {"spec_kind": kind,
            "spec_version": str(doc.get("openapi") or doc.get("swagger"))[:20],
            "title": str(info.get("title") or "")[:200],
            "api_version": str(info.get("version") or "")[:50]}
