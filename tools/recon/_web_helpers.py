"""_web_helpers — shared HTTP utilities for tier5_web scanners."""
import asyncio, ssl, urllib.request, urllib.error

UA = "VulnusLab-Recon/1.0"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE  # allow self-signed for probes

def _normalize(target):
    t = target.strip()
    if not t.startswith(("http://","https://")):
        t = "https://" + t
    return t.rstrip("/")

async def fetch(url, method="GET", headers=None, body=None, timeout=4):
    """Returns (status_code, headers_dict, body_bytes). 0 status on error."""
    hd = {"User-Agent": UA}
    if headers: hd.update(headers)
    def _do():
        try:
            req = urllib.request.Request(url, method=method, headers=hd, data=body)
            with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
                return r.status, dict(r.headers), r.read(128*1024)
        except urllib.error.HTTPError as e:
            try: bb = e.read(128*1024)
            except: bb = b""
            return e.code, dict(e.headers or {}), bb
        except Exception:
            return 0, {}, b""
    return await asyncio.to_thread(_do)

def base_url(host):
    return _normalize(host)
