"""_dns_helpers — shared utilities for tier2_dns scanners (zero-FP DNS toolkit)."""
import asyncio
import dns.resolver
import dns.zone
import dns.query
import dns.exception

DEFAULT_TIMEOUT = 3

async def query(host, rdtype):
    """Query DNS RR type. Return list of stringified records; [] on any error."""
    try:
        ans = await asyncio.to_thread(dns.resolver.resolve, host, rdtype, lifetime=DEFAULT_TIMEOUT)
        return [str(r) for r in ans]
    except Exception:
        return []

async def resolve_ns(host):
    try:
        ans = await asyncio.to_thread(dns.resolver.resolve, host, "NS", lifetime=DEFAULT_TIMEOUT)
        return sorted({str(r).rstrip(".") for r in ans})
    except Exception:
        return []

async def query_at(server_ip, host, rdtype, recurse=True):
    """Direct query against a specific resolver (for cache snoop / 0x20)."""
    try:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [server_ip]
        r.lifetime = DEFAULT_TIMEOUT
        flags = 0 if recurse else dns.flags.RD ^ dns.flags.RD  # noqa
        ans = await asyncio.to_thread(r.resolve, host, rdtype)
        return [str(rr) for rr in ans]
    except Exception:
        return []
