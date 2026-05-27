"""_network_helpers — TCP/UDP probes for §9 Network."""
import asyncio, socket

async def tcp_open(host, port, timeout=3):
    def _do():
        try:
            with socket.create_connection((host, port), timeout=timeout): return True
        except Exception: return False
    return await asyncio.to_thread(_do)

async def tcp_banner(host, port, timeout=3, send=b""):
    def _do():
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                if send: s.send(send)
                return s.recv(1024)
        except Exception: return b""
    return await asyncio.to_thread(_do)

async def udp_probe(host, port, payload, timeout=3):
    def _do():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
            s.sendto(payload, (host, port))
            data,_ = s.recvfrom(1024); s.close(); return data
        except Exception: return b""
    return await asyncio.to_thread(_do)

def resolve_host(target):
    try:
        h = target.replace("http://","").replace("https://","").split("/")[0].split(":")[0]
        return socket.gethostbyname(h)
    except Exception:
        return ""
