"""_osint_helpers — JSON/HTML fetch + URL build for §4/§7."""
import asyncio, urllib.request, urllib.parse, json, ssl

CTX = ssl.create_default_context(); CTX.check_hostname=False; CTX.verify_mode=ssl.CERT_NONE
UA = "Mozilla/5.0 (compatible; VulnusLab-Recon/1.0)"

async def get_json(url, headers=None, timeout=8):
    def _do():
        hd = {"User-Agent": UA, "Accept": "application/json"}
        if headers: hd.update(headers)
        try:
            req = urllib.request.Request(url, headers=hd)
            with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            try: return e.code, json.loads(e.read())
            except Exception: return e.code, {}
        except Exception as e: return 0, {"_error": str(e)[:120]}
    return await asyncio.to_thread(_do)

async def get_text(url, headers=None, timeout=8):
    def _do():
        hd = {"User-Agent": UA}
        if headers: hd.update(headers)
        try:
            req = urllib.request.Request(url, headers=hd)
            with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
                return r.status, r.read(64*1024).decode("utf-8","ignore")
        except urllib.error.HTTPError as e:
            try: return e.code, e.read(64*1024).decode("utf-8","ignore")
            except Exception: return e.code, ""
        except Exception: return 0, ""
    return await asyncio.to_thread(_do)
