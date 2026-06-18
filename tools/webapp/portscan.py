"""Fast Port Scan — VL-FORGE pattern.

Route: /api/recon/masscan  (frontend tool key: "masscan")

Probes the top 40 most security-relevant ports via TCP connect.
Faster than Deep Port Scan (~5 sec vs ~30 sec). Returns named findings
covering: databases exposed, admin ports exposed, DevOps panels, file-
shares, cleartext legacy protocols.

ZERO-FP PANEL CONFIRMATION
--------------------------
A graded "admin/DevOps panel exposed" finding is emitted ONLY when an
actual HTTP fetch of the open port returns a response that identifies a
known admin/devops panel (Jenkins / Kibana / Grafana / Docker-API / etc.
login page or banner signature). A bare open TCP port — with NO confirmed
panel behind it — is reported as INFO ("port N open"), never HIGH. This
stops the old behaviour where the scanner guessed the service from the
port number alone (e.g. calling Juice Shop's own :3000 "Grafana" or a
Cloudflare :8080 an "admin panel").

Additional guards:
  * The target's own primary app port (the HTTP/HTTPS port the user is
    actually testing) is never flagged as an exposed admin panel.
  * If the host resolves to a known CDN edge (Cloudflare / Akamai /
    Fastly), the open ports belong to the CDN, not the customer origin —
    they are reported INFO with a CDN note, never graded.

Sources (parallel):
  1. TCP probe per port (~40 in parallel)
  2. DNS resolution to IP
  3. HTTP confirmation fetch per open web-capable port (panel signatures)

Findings (~12 rules from tools/_payloads/portscan_findings.py):
  CRITICAL: databases exposed
  HIGH    : admin ports exposed, CONFIRMED DevOps panels, file-shares, legacy cleartext
  MEDIUM  : HTTP without HTTPS
  POSITIVE: HTTPS available, no ports open (filtered)
  INFO    : total open count, unconfirmed open web ports, CDN edge ports
"""
import asyncio
import re
import socket
import ssl

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.portscan_findings import (
    PORTSCAN_FINDING_RULES, PORT_CATALOG, _DATABASE_PORTS,
)
from tools._vl_core.portscan_engine import tcp_probe
from tools._vl_core.verify import vl_verify

router = APIRouter()


# ── Web-capable ports worth an HTTP confirmation fetch ──
_HTTP_PORTS = {80, 81, 591, 2375, 2376, 2480, 3000, 5601, 7474, 8000, 8008,
               8080, 8081, 8086, 8088, 8443, 8888, 9000, 9090, 9200, 9300,
               15672, 16686}
_TLS_PORTS = {443, 8443, 2376, 9300}  # fetch over TLS

# CDN edge signatures — Server / Via / header tokens that PROVE the port we
# reached is a shared CDN edge, not the customer origin.
_CDN_SIGNATURES = {
    "cloudflare":  [r"server:\s*cloudflare", r"\bcf-ray\b", r"\b__cf"],
    "akamai":      [r"server:\s*akamaighost", r"\bx-akamai", r"\bakamai\b"],
    "fastly":      [r"server:\s*fastly", r"x-served-by:\s*cache-", r"\bfastly\b",
                    r"x-fastly"],
}

# Admin / DevOps panel CONFIRMATION signatures. A panel is only graded HIGH
# when the live HTTP body / headers actually match one of these. Each entry:
#   name -> list of regexes (any match on the lowercased response confirms it)
_PANEL_SIGNATURES = {
    "Jenkins": [
        r"x-jenkins:", r"<title>[^<]*jenkins", r'data-version="[\d.]+".{0,80}jenkins',
        r"/static/[^\"']+/jenkins", r"jenkins-session",
    ],
    "Grafana": [
        r"<title>grafana</title>", r'grafana-app', r'"appsuburl"', r'grafanabootdata',
        r"x-grafana", r'name="application-name" content="grafana"',
    ],
    "Kibana": [
        r"<title>kibana</title>", r"kbn-name", r"kbn-version", r'"kibana"',
        r"x-kbn-", r'data-test-subj="kibana',
    ],
    "Docker API": [
        r'"apiversion"\s*:', r'"dockerrootdir"', r'\{"message":"page not found"\}',
        r'"serverversion"', r'"ostype"\s*:\s*"linux"',
    ],
    "Kubernetes API": [
        r'"kind"\s*:\s*"status"', r'"apiversion"\s*:\s*"v1"',
        r"k8s\.io", r'forbidden.{0,40}system:anonymous',
    ],
    "Prometheus": [
        r"<title>prometheus", r"/graph\"", r"prometheus_build_info",
        r'name="robots" content="noindex,nofollow"\s*/?>\s*<title>prometheus',
    ],
    "Elasticsearch": [
        r'"cluster_name"', r'"lucene_version"', r'"tagline"\s*:\s*"you know, for search"',
    ],
    "RabbitMQ Management": [
        r"rabbitmq management", r'<title>rabbitmq', r"/api/whoami",
    ],
    "Neo4j": [
        r'"neo4j_version"', r"<title>neo4j", r'"bolt_routing"',
    ],
    "PHPMyAdmin": [
        r"phpmyadmin", r"pma_username", r"<title>phpmyadmin",
    ],
    "Portainer": [
        r"<title>portainer", r"portainer\.io", r'ng-app="portainer"',
    ],
    "Adminer": [
        r"<title>[^<]*adminer", r"adminer\.org", r'name="auth\[server\]"',
    ],
    "Traefik Dashboard": [
        r"<title>traefik", r'ng-app="traefik"', r"traefik-",
    ],
    "Spring Boot Actuator": [
        r'"_links"\s*:.{0,200}"health"', r'"status"\s*:\s*"up"', r'"diskspace"',
    ],
    "Jupyter": [
        r"<title>jupyter", r"jupyterhub", r'data-base-url=', r"_xsrf",
    ],
    "Consul": [
        r"<title>consul", r'"consulservice"', r"/v1/agent/self",
    ],
    "MinIO Console": [
        r"<title>minio", r"minio console", r'minio\.',
    ],
    "Argo CD": [
        r"<title>argo cd", r"argocd", r'data-app-name="argo-cd"',
    ],
    "Generic admin login": [
        r"<title>[^<]*(admin|sign in|log\s?in|dashboard)[^<]*</title>",
    ],
}


async def _http_confirm(ip: str, host: str, port: int, timeout: float = 4.0):
    """Fetch a port over HTTP(S) and return (raw_response_lower, status_line).

    Sends a real GET / so we can read the body and headers, then match panel
    and CDN signatures against the actual response. Returns ("", "") on any
    connection / TLS error (treated as "no confirmation").
    """
    use_tls = port in _TLS_PORTS
    try:
        if use_tls:
            sslctx = ssl.create_default_context()
            sslctx.check_hostname = False
            sslctx.verify_mode = ssl.CERT_NONE
            fut = asyncio.open_connection(ip, port, ssl=sslctx,
                                          server_hostname=host)
        else:
            fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
    except Exception:
        return "", ""
    try:
        req = (b"GET / HTTP/1.1\r\nHost: " + host.encode() +
               b"\r\nUser-Agent: VulnusLab-PortScan\r\nAccept: */*\r\n"
               b"Connection: close\r\n\r\n")
        writer.write(req)
        await writer.drain()
        chunks = []
        total = 0
        # Read up to ~16KB — enough for headers + the start of a panel body.
        while total < 16384:
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            except Exception:
                break
            if not data:
                break
            chunks.append(data)
            total += len(data)
        raw = b"".join(chunks).decode("utf-8", errors="replace")
        status = raw.split("\r\n", 1)[0].strip() if raw else ""
        return raw.lower(), status
    except Exception:
        return "", ""
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


def _detect_cdn(raw_lower: str):
    """Return the CDN name if the response proves a known CDN edge, else None."""
    if not raw_lower:
        return None
    for cdn, pats in _CDN_SIGNATURES.items():
        for pat in pats:
            if re.search(pat, raw_lower):
                return cdn
    return None


def _detect_panel(raw_lower: str):
    """Return the confirmed panel name if the response matches a known
    admin/devops panel signature, else None. Body/header proof only."""
    if not raw_lower:
        return None
    for name, pats in _PANEL_SIGNATURES.items():
        for pat in pats:
            try:
                if re.search(pat, raw_lower):
                    return name
            except re.error:
                continue
    return None


def _primary_app_port(req_target: str, open_ports):
    """Best-effort identification of the target's OWN primary app port.

    If the user supplied an explicit port (e.g. http://host:3000), that IS
    the app under test and must never be flagged as an exposed panel.
    Otherwise the canonical web port (443 > 80) is the app's own port.
    """
    # Explicit port in the target string wins.
    m = re.search(r":(\d{2,5})(?:/|$)", req_target or "")
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            pass
    open_set = {p["port"] for p in (open_ports or [])}
    for canonical in (443, 80, 8443, 8080):
        if canonical in open_set:
            return canonical
    return None


async def gather(ctx: ScanContext, req_target: str = ""):
    host = ctx.host

    # Resolve to IP
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return
    ctx.state["ip"] = ip
    ctx.source("dns-resolve")

    # Probe the top ~40 catalog ports in parallel
    ports = sorted(PORT_CATALOG.keys())
    results = await asyncio.gather(*[tcp_probe(ip, p, timeout=2.0) for p in ports])
    open_ports = []
    for port, is_open in zip(ports, results):
        if not is_open: continue
        svc, sev, cwe = PORT_CATALOG[port]
        open_ports.append({"port": port, "service": svc, "severity": sev, "cwe": cwe})

    ctx.state["ports_open"] = open_ports
    ctx.state["ports_probed"] = len(ports)
    ctx.state["http_present"] = any(p["port"] in (80, 8080, 8000) for p in open_ports)
    ctx.state["https_present"] = any(p["port"] in (443, 8443) for p in open_ports)

    if ports:
        ctx.source(f"tcp-connect-{len(ports)}-ports")

    # ── Primary app port (never flagged as an exposed panel) ──
    primary = _primary_app_port(req_target, open_ports)
    ctx.state["primary_app_port"] = primary

    # ── HTTP confirmation pass over open web-capable ports ──
    # A DevOps/admin panel is graded HIGH ONLY when the live response proves
    # a known panel signature. We also use these fetches to detect a CDN edge.
    confirmed_panels = []          # [{port, panel, service, evidence}]
    unconfirmed_web_ports = []     # open web ports with NO panel proof -> INFO
    cdn_name = None

    web_open = [p for p in open_ports if p["port"] in _HTTP_PORTS or p["port"] in _TLS_PORTS]
    # Always fetch 80/443 too (for CDN detection) even if not "interesting".
    for canonical in (80, 443):
        if any(p["port"] == canonical for p in open_ports) and \
           not any(p["port"] == canonical for p in web_open):
            web_open.append(next(p for p in open_ports if p["port"] == canonical))

    if web_open:
        fetches = await asyncio.gather(
            *[_http_confirm(ip, host, p["port"]) for p in web_open],
            return_exceptions=True,
        )
        for p, res in zip(web_open, fetches):
            if isinstance(res, Exception) or not isinstance(res, tuple):
                continue
            raw_lower, status = res
            # CDN check first — a confirmed CDN edge overrides panel grading.
            this_cdn = _detect_cdn(raw_lower)
            if this_cdn and not cdn_name:
                cdn_name = this_cdn
            if not raw_lower:
                continue
            panel = _detect_panel(raw_lower)
            port_no = p["port"]
            # Database ports (9200 Elasticsearch, 5984 CouchDB, 7474 Neo4j, …)
            # are already graded by rule_databases_exposed — don't also grade
            # them here as a DevOps panel (avoids double-counting one service).
            if port_no in _DATABASE_PORTS:
                continue
            if panel and port_no != primary and not this_cdn:
                confirmed_panels.append({
                    "port": port_no,
                    "panel": panel,
                    "service": p.get("service", "?"),
                    "evidence": f"HTTP {status or 'response'} on :{port_no} "
                                f"matched {panel} signature",
                })
            elif port_no != primary and not this_cdn:
                # Open web port, responded, but NO panel proof -> INFO only.
                unconfirmed_web_ports.append({
                    "port": port_no,
                    "service": p.get("service", "?"),
                    "status": status or "open (no panel signature)",
                })

    ctx.state["confirmed_panels"] = confirmed_panels
    ctx.state["unconfirmed_web_ports"] = unconfirmed_web_ports
    ctx.state["cdn"] = cdn_name
    if confirmed_panels:
        ctx.source(f"http-confirm-{len(confirmed_panels)}-panels")
    if cdn_name:
        ctx.source(f"cdn-edge-{cdn_name}")

    # Backwards-compat: top-level ports[] list for existing PDF section
    ctx.state["ports"] = [{"port": p["port"], "proto": "tcp", "state": "open",
                            "service": p["service"]} for p in open_ports]


INTEL_FIELDS = [
    ("IP address",          "ip"),
    ("Ports probed",         "ports_probed"),
    ("Open ports",           "open_ports_display"),
    ("HTTP / HTTPS",         "http_https_display"),
    ("Primary app port",     "primary_app_port"),
    ("CDN edge",             "cdn"),
    ("Confirmed panels",     "confirmed_panels_display"),
]


# WAP-isolated copy — only registers /api/webapp/scan/portscan. The Recon
# module keeps its own portscan at /api/recon/masscan in tools/recon/.
@router.post("/api/webapp/scan/portscan")
@vl_verify()
async def webapp_portscan(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx, req_target=req.target)
        op = ctx.state.get("ports_open") or []
        if op:
            ctx.state["open_ports_display"] = ", ".join(
                f"{p['port']}/{p['service']}" for p in op[:10])
        ctx.state["http_https_display"] = (
            f"HTTP={ctx.state.get('http_present')}, "
            f"HTTPS={ctx.state.get('https_present')}")
        cp = ctx.state.get("confirmed_panels") or []
        if cp:
            ctx.state["confirmed_panels_display"] = ", ".join(
                f"{c['panel']}:{c['port']}" for c in cp[:10])

    return await run_scanner(
        host=host, tool="portscan",
        gather_func=gather_with_display,
        finding_rules=PORTSCAN_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["ports", "ip", "ports_open", "confirmed_panels", "cdn"],
    )


def register(app):
    app.include_router(router)
