"""_subdomain_helpers — shared utilities for tier3_subdomain scanners."""
import asyncio
import dns.resolver

DEFAULT_TIMEOUT = 4

async def resolves(host):
    for rtype in ("A","AAAA"):
        try:
            await asyncio.to_thread(dns.resolver.resolve, host, rtype, lifetime=DEFAULT_TIMEOUT)
            return True
        except Exception:
            pass
    return False

async def bulk_check(hosts, concurrency=20):
    sem = asyncio.Semaphore(concurrency)
    async def _c(h):
        async with sem:
            return h if await resolves(h) else None
    res = await asyncio.gather(*[_c(h) for h in hosts], return_exceptions=True)
    return sorted({r for r in res if isinstance(r,str)})
