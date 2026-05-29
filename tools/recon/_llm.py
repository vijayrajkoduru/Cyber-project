"""
tools/recon/_llm.py - shared Claude (Anthropic) helper for AI-assisted recon scanners.

Zero hard dependency: uses stdlib urllib so it works even without the
`anthropic` SDK. Key-gated via ANTHROPIC_API_KEY; degrades gracefully
(returns None / []) on missing key, network error, or bad response so callers
can emit an honest "set ANTHROPIC_API_KEY to enable" INFO instead of failing.
"""
import os
import json
import urllib.request
import urllib.error

_API_URL = "https://api.anthropic.com/v1/messages"
_DEFAULT_MODEL = os.environ.get("VL_LLM_MODEL", "claude-haiku-4-5-20251001")
_VERSION = "2023-06-01"


def llm_key():
    return os.environ.get("ANTHROPIC_API_KEY", "").strip()


def llm_available():
    return bool(llm_key())


def ask_claude(prompt, system=None, max_tokens=1024, model=None, temperature=0.0, timeout=30):
    """Call the Anthropic Messages API. Returns assistant text, or None on any
    failure (missing key, network error, non-200, malformed response)."""
    key = llm_key()
    if not key:
        return None
    body = {
        "model": model or _DEFAULT_MODEL,
        "max_tokens": int(max_tokens),
        "temperature": float(temperature),
        "messages": [{"role": "user", "content": str(prompt)}],
    }
    if system:
        body["system"] = str(system)
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(_API_URL, data=data, method="POST")
    req.add_header("content-type", "application/json")
    req.add_header("anthropic-version", _VERSION)
    req.add_header("x-api-key", key)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError, OSError):
        return None
    try:
        parts = payload.get("content") or []
        text = "".join(p.get("text", "") for p in parts if isinstance(p, dict))
        return text.strip() or None
    except (AttributeError, TypeError):
        return None


def _extract_json(text):
    """Pull the first JSON array/object out of an LLM response that may be
    wrapped in prose or ```json fences."""
    if not text:
        return None
    t = text.strip()
    if t.startswith("```"):
        seg = t.split("```")
        t = seg[1] if len(seg) > 1 else text
        if t.lstrip().lower().startswith("json"):
            t = t.lstrip()[4:]
    t = t.strip()
    try:
        return json.loads(t)
    except ValueError:
        pass
    for op, cl in (("[", "]"), ("{", "}")):
        i, j = t.find(op), t.rfind(cl)
        if 0 <= i < j:
            try:
                return json.loads(t[i:j + 1])
            except ValueError:
                continue
    return None


def ask_claude_list(prompt, system=None, max_tokens=1024, cap=200, timeout=30):
    """Ask Claude for a JSON array; returns a de-duped capped list of strings,
    or [] on failure. Callers treat [] as 'no AI output'."""
    txt = ask_claude(prompt, system=system, max_tokens=max_tokens, timeout=timeout)
    parsed = _extract_json(txt)
    out = []
    if isinstance(parsed, list):
        for item in parsed:
            if isinstance(item, str):
                s = item.strip()
            elif isinstance(item, dict):
                s = str(item.get("path") or item.get("value") or item.get("name") or "").strip()
            else:
                s = str(item).strip()
            if s:
                out.append(s)
    seen, uniq = set(), []
    for s in out:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
        if len(uniq) >= cap:
            break
    return uniq


async def ask_claude_async(prompt, **kw):
    import asyncio
    return await asyncio.to_thread(ask_claude, prompt, **kw)


async def ask_claude_list_async(prompt, **kw):
    import asyncio
    return await asyncio.to_thread(ask_claude_list, prompt, **kw)
