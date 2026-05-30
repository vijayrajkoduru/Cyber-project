"""tools/vuln/_vuln_common.py - shared probe helpers for Vuln scanners.
Underscore-prefixed so the autoloader skips it (helper, not a scanner)."""
import json
import socket
import ssl
import urllib.error
import urllib.request

_UA = "Mozilla/5.0 (VulnusLab Vuln)"
_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE


def tcp_probe(host, port, payload=b"", read=256, timeout=4):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except Exception:
        return False, b""
    try:
        if payload:
            s.sendall(payload)
        s.settimeout(timeout)
        try:
            data = s.recv(read)
        except Exception:
            data = b""
        return True, data
    finally:
        try:
            s.close()
        except Exception:
            pass


def port_open(host, port, timeout=4):
    ok, _ = tcp_probe(host, port, b"", 1, timeout)
    return ok


def http_get(url, timeout=10, read=200000):
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as r:
            body = r.read(read)
            return {"status": r.status,
                    "headers": {k.lower(): v for k, v in r.headers.items()},
                    "body": body.decode("utf-8", "ignore")}
    except urllib.error.HTTPError as e:
        hdrs = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        return {"status": e.code, "headers": hdrs, "body": ""}
    except Exception:
        return None


def http_json(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as r:
            return json.loads(r.read().decode("utf-8", "ignore"))
    except Exception:
        return None
