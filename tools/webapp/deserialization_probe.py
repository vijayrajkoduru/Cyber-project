"""Webapp: Insecure deserialization marker probe (PHP / Java / Python / .NET)."""
import re
import base64
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response

router = APIRouter()

# AI-curated 53-entry marker list — covers Java/Python/PHP/.NET/Ruby/Node markers
try:
    from tools._payloads.deserialization_payloads import DESERIALIZATION_PAYLOADS as _AI_DS
    _AI_MARKERS = [(p["marker"], p.get("language", "unknown"))
                   for p in _AI_DS if isinstance(p, dict) and p.get("marker")]
except Exception:
    _AI_MARKERS = []


def _looks_like_serialized(value):
    """Return (engine, snippet) if value looks like a serialized object."""
    if not value or len(value) < 4:
        return None
    # PHP serialized: O:8:"stdClass":1:{...}  or  a:2:{s:4:"name";...}
    if re.match(r'^[Oa]:\d+:["{]', value):
        return ("PHP serialize()", value[:80])
    # Java serialized: starts with ACED 0005 (rO0AB if base64-encoded)
    if value.startswith("\xac\xed\x00\x05") or value.startswith("rO0AB"):
        return ("Java serialize", value[:60])
    # Python pickle: starts with \x80 (protocol byte)
    if value[:1] in ("\x80", "(") and value[1:2] in ("\x02","\x03","\x04","\x05"):
        return ("Python pickle", value[:60])
    # .NET ViewState: __VIEWSTATE param, base64, starts with /w
    if value.startswith("/wEP"):
        return (".NET ViewState", value[:60])
    # Base64 decode attempt for Java/Python
    try:
        decoded = base64.b64decode(value[:200], validate=False)
        if decoded.startswith(b"\xac\xed\x00\x05"):
            return ("Java serialize (base64)", value[:60])
        if decoded[:1] == b"\x80" and decoded[1:2] in (b"\x02",b"\x03",b"\x04",b"\x05"):
            return ("Python pickle (base64)", value[:60])
    except Exception:
        pass
    # AI-curated marker substring check — catches less-common gadget signatures
    # (XStream, PHPMailer, ysoserial, BinaryFormatter, ObjectDataProvider, etc.)
    for _mk, _lang in _AI_MARKERS:
        if _mk and len(_mk) >= 4 and _mk in value:
            return (f"AI-marker:{_lang}", value[:80])
    return None


@router.post("/api/webapp/deserialization_probe")
async def webapp_deserialization_probe(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    tests = 0
    detected = []
    
    # Probe: homepage + common endpoints
    probes = ["/","/login","/dashboard","/profile","/api","/admin"]
    for path in probes:
        tests += 1
        r = safe_get(base + path, req=req, allow_redirects=True, timeout=6)
        if r is None:
            continue
        # Check Set-Cookie values
        for c in r.cookies:
            res = _looks_like_serialized(c.value)
            if res:
                engine, snippet = res
                detected.append({"location": f"Set-Cookie: {c.name}", "engine": engine})
                findings.append(wrap_finding(
                    f"Suspected serialized payload in cookie '{c.name}' - {engine}",
                    "HIGH",
                    cvss="8.1", cwe="CWE-502",
                    cwe_name="Deserialization of Untrusted Data",
                    owasp="A08:2021",
                    remediation=("Never deserialize user-controlled data. Use JSON / structured formats. "
                                 "If serialization is required, sign+HMAC the payload server-side and "
                                 "verify before deserializing. PHP: avoid unserialize(); use JSON. "
                                 "Java: avoid ObjectInputStream on untrusted streams. Python: never "
                                 "pickle.loads() from network input."),
                    evidence_marker=f"GET {path} -> Set-Cookie '{c.name}' contains {engine} payload: {snippet}",
                ))
        # Check body for ViewState / serialized fields
        body = r.text or ""
        vs = re.search(r'name="?__VIEWSTATE"?[^>]*value="?(/wEP[A-Za-z0-9+/=]+)', body)
        if vs:
            detected.append({"location": "Body (__VIEWSTATE)", "engine": ".NET"})
            findings.append(wrap_finding(
                f"ASP.NET __VIEWSTATE present at {path} - if signing disabled, deserialization RCE possible",
                "MEDIUM",
                cvss="6.5", cwe="CWE-502",
                cwe_name="Deserialization of Untrusted Data",
                owasp="A08:2021",
                remediation="Enable ViewState MAC (default in modern ASP.NET) and rotate machine keys. Disable EnableViewStateMac=false.",
                evidence_marker=f"GET {path} -> __VIEWSTATE field present",
            ))

    return standard_response(
        tool="deserialization_probe", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Probed {tests} endpoints for serialized-payload markers (PHP/Java/Python/.NET)",
        raw_data={"deserialization_probe": {"detected": detected}},
    )


def register(app):
    app.include_router(router)
