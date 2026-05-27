"""_threat_helpers — API call wrapper for §8 threat-intel scanners."""
import asyncio, urllib.request, urllib.parse, json, ssl

CTX = ssl.create_default_context(); CTX.check_hostname=False; CTX.verify_mode=ssl.CERT_NONE

async def api_get(url, headers=None, timeout=10):
    def _do():
        try:
            req = urllib.request.Request(url, headers=headers or {})
            with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            try: body = json.loads(e.read())
            except: body = {}
            return e.code, body
        except Exception as e:
            return 0, {"_error": str(e)[:120]}
    return await asyncio.to_thread(_do)
