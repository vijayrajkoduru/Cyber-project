"""deserialization_payloads — handcrafted dev-time. Webapp module asset.

Probe markers for detecting deserialization-vulnerable endpoints. These are
DETECTION patterns only — they identify endpoints that ACCEPT and PARSE
serialized data (so a follow-up gadget chain could be developed). They do
NOT carry executable gadgets; the scanner only checks whether the endpoint
appears to deserialize what we send.

Each entry: {marker, language, context, severity}.
"""

DESERIALIZATION_PAYLOADS = [
    # ── Java (ObjectInputStream / ysoserial markers — magic bytes only) ─────
    # Java serialized data starts with 0xAC 0xED 0x00 0x05 (STREAM_MAGIC + STREAM_VERSION)
    {"marker": "rO0AB", "language": "java", "context": "param",
     "severity": "CRITICAL"},  # base64-encoded ObjectInputStream header
    {"marker": "rO0ABQ", "language": "java", "context": "cookie",
     "severity": "CRITICAL"},
    {"marker": "rO0ABQ==", "language": "java", "context": "body",
     "severity": "CRITICAL"},
    {"marker": "%aced%0005%0000", "language": "java", "context": "param",
     "severity": "CRITICAL"},  # URL-encoded raw bytes
    {"marker": "_ViewState__", "language": "java", "context": "param",
     "severity": "HIGH"},  # WebSphere viewstate variant
    {"marker": "ysoserial.payloads.CommonsCollections", "language": "java", "context": "body",
     "severity": "CRITICAL"},  # echo-check marker (passive)
    {"marker": "java.rmi.MarshalledObject", "language": "java", "context": "body",
     "severity": "HIGH"},
    {"marker": "javax.management.BadAttributeValueExpException", "language": "java", "context": "body",
     "severity": "HIGH"},
    {"marker": "org.apache.commons.collections.functors", "language": "java", "context": "body",
     "severity": "HIGH"},
    {"marker": "sun.reflect.annotation.AnnotationInvocationHandler", "language": "java", "context": "body",
     "severity": "HIGH"},
    {"marker": "javax.xml.transform.Templates", "language": "java", "context": "body",
     "severity": "HIGH"},
    {"marker": "java.io.ObjectInputStream", "language": "java", "context": "body",
     "severity": "MEDIUM"},
    {"marker": "xstream.alias", "language": "java", "context": "body",
     "severity": "MEDIUM"},  # XStream-vulnerable framework signal
    {"marker": "<dynamic-proxy>", "language": "java", "context": "body",
     "severity": "HIGH"},  # XStream dynamic proxy gadget marker

    # ── Python (pickle markers) ─────────────────────────────────────────────
    # Pickle protocols 0-5 — magic bytes \x80\x02..\x80\x05
    {"marker": "gASV", "language": "python", "context": "param",
     "severity": "CRITICAL"},  # base64 of \x80\x04\x95 (pickle proto 4)
    {"marker": "gAOV", "language": "python", "context": "param",
     "severity": "CRITICAL"},  # \x80\x03 (pickle proto 3)
    {"marker": "gAJ", "language": "python", "context": "cookie",
     "severity": "CRITICAL"},  # \x80\x02 (pickle proto 2)
    {"marker": "%80%04%95", "language": "python", "context": "param",
     "severity": "CRITICAL"},  # URL-encoded pickle magic
    {"marker": "__reduce__", "language": "python", "context": "body",
     "severity": "HIGH"},
    {"marker": "__reduce_ex__", "language": "python", "context": "body",
     "severity": "HIGH"},
    {"marker": "subprocess.Popen", "language": "python", "context": "body",
     "severity": "CRITICAL"},  # Common pickle RCE gadget signature
    {"marker": "posix.system", "language": "python", "context": "body",
     "severity": "CRITICAL"},
    {"marker": "yaml.unsafe_load", "language": "python", "context": "body",
     "severity": "HIGH"},  # PyYAML RCE marker
    {"marker": "!!python/object", "language": "python", "context": "body",
     "severity": "CRITICAL"},  # YAML python-object tag — RCE-prone

    # ── PHP (unserialize markers — O:N:"...":N:{...}) ───────────────────────
    {"marker": "O:8:\"stdClass\"", "language": "php", "context": "cookie",
     "severity": "HIGH"},  # PHP serialized stdClass
    {"marker": "O:16:\"PHPMailer", "language": "php", "context": "param",
     "severity": "CRITICAL"},  # PHPMailer gadget chain marker
    {"marker": "a:1:{i:0;", "language": "php", "context": "cookie",
     "severity": "MEDIUM"},  # PHP array serialization
    {"marker": "s:6:\"length", "language": "php", "context": "body",
     "severity": "MEDIUM"},
    {"marker": "C:11:\"ArrayObject\"", "language": "php", "context": "body",
     "severity": "HIGH"},  # ArrayObject gadget marker
    {"marker": "__destruct", "language": "php", "context": "body",
     "severity": "HIGH"},  # Magic method invoked on unserialize
    {"marker": "__wakeup", "language": "php", "context": "body",
     "severity": "HIGH"},
    {"marker": "__toString", "language": "php", "context": "body",
     "severity": "MEDIUM"},
    {"marker": "Object(stdClass)", "language": "php", "context": "body",
     "severity": "MEDIUM"},
    {"marker": "phar://", "language": "php", "context": "param",
     "severity": "CRITICAL"},  # PHAR deserialization vector
    {"marker": "phar://test.phar", "language": "php", "context": "param",
     "severity": "HIGH"},
    {"marker": "data:text/plain;base64,", "language": "php", "context": "param",
     "severity": "MEDIUM"},  # phar+stream wrapper

    # ── .NET (BinaryFormatter / ObjectStateFormatter / __VIEWSTATE) ─────────
    {"marker": "__VIEWSTATE", "language": "dotnet", "context": "param",
     "severity": "CRITICAL"},  # ASP.NET ViewState
    {"marker": "/wEPDw", "language": "dotnet", "context": "param",
     "severity": "CRITICAL"},  # ViewState base64 prefix
    {"marker": "AAEAAAD/////", "language": "dotnet", "context": "cookie",
     "severity": "CRITICAL"},  # BinaryFormatter header
    {"marker": "BinaryFormatter", "language": "dotnet", "context": "body",
     "severity": "CRITICAL"},
    {"marker": "ObjectStateFormatter", "language": "dotnet", "context": "body",
     "severity": "CRITICAL"},
    {"marker": "SoapFormatter", "language": "dotnet", "context": "body",
     "severity": "HIGH"},
    {"marker": "System.Windows.Data.ObjectDataProvider", "language": "dotnet", "context": "body",
     "severity": "CRITICAL"},  # ysoserial.net gadget
    {"marker": "JavaScriptSerializer", "language": "dotnet", "context": "body",
     "severity": "HIGH"},

    # ── Ruby Marshal ────────────────────────────────────────────────────────
    {"marker": "\\x04\\x08", "language": "ruby", "context": "cookie",
     "severity": "CRITICAL"},  # Ruby Marshal header
    {"marker": "BAh7", "language": "ruby", "context": "cookie",
     "severity": "CRITICAL"},  # base64 of \x04\x08{
    {"marker": "_ActionDispatch::Cookies::CookieJar", "language": "ruby", "context": "cookie",
     "severity": "HIGH"},
    {"marker": "Gem::SpecFetcher", "language": "ruby", "context": "body",
     "severity": "CRITICAL"},  # Universal Ruby gadget
    {"marker": "ERB.new", "language": "ruby", "context": "body",
     "severity": "HIGH"},

    # ── Node.js node-serialize ──────────────────────────────────────────────
    {"marker": "_$$ND_FUNC$$_", "language": "node", "context": "body",
     "severity": "CRITICAL"},  # node-serialize RCE marker
    {"marker": "function(){return", "language": "node", "context": "body",
     "severity": "HIGH"},
    {"marker": "child_process.exec", "language": "node", "context": "body",
     "severity": "CRITICAL"},
    {"marker": "require('child_process')", "language": "node", "context": "body",
     "severity": "HIGH"},
]
