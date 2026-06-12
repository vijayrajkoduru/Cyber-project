"""docker_api_exposure_probe - findings rules.

Severity model:
  CRITICAL - a real Docker Engine /version JSON was retrieved over an
             UNAUTHENTICATED channel (TCP 2375 plaintext, or 2376 with no
             client-cert requirement). Direct host-takeover primitive.
             Stamped verified_exploit=True (we actually pulled the API
             response) so the advisory-cap does not clamp it.
  INFO     - port open but NOT a Docker /version JSON (some other service),
             or probe could not run / target unreachable.
  POSITIVE - 2376 demanded a TLS client certificate (mTLS) or the API
             answered 401/403 -> the engine is access-controlled.

Zero-FP: CRITICAL fires ONLY on docker_unauth (a parsed Docker Engine
version payload). Open-port-without-Docker-JSON never grades above INFO.
"""


def rule_docker_unauth_exposed(s):
    hits = s.get("docker_unauth_hits") or []
    if not hits:
        return None
    h = hits[0]
    ports = ", ".join(str(x.get("port")) for x in hits)
    return {
        "name": ("Docker Engine remote API exposed without authentication "
                 "(host-takeover primitive)"),
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe":  "CWE-306",
        "cwe_name": "Missing Authentication for Critical Function",
        "owasp": "A01:2021",
        "verified_exploit": True,
        "evidence": (
            f"{s.get('docker_target', '?')} answered an unauthenticated GET "
            f"/version on TCP {ports} with a valid Docker Engine payload: "
            f"ApiVersion={h.get('api_version') or '?'}, "
            f"Version={h.get('engine_version') or '?'}, "
            f"Os={h.get('os') or '?'}, KernelVersion={h.get('kernel_version') or '?'}. "
            "Any network-adjacent actor can create a container that bind-mounts "
            "the host root filesystem (-v /:/host) and obtain root on the host, "
            "or escape to other tenants on the engine. No credentials were sent "
            "by this probe; the /version response alone proves the API is open. "
            "MITRE ATT&CK T1610 (Deploy Container) / T1611 (Escape to Host)."
        ),
        "remediation": (
            "1. Stop exposing the Docker daemon on a TCP socket. Bind the "
            "engine to the local unix socket only (remove '-H tcp://0.0.0.0:2375' "
            "from dockerd flags / /etc/docker/daemon.json 'hosts'). "
            "2. If remote management is required, enable mutual-TLS: generate a "
            "CA + server cert + per-client certs and run dockerd with "
            "--tlsverify --tlscacert --tlscert --tlskey on 2376; reject 2375 "
            "entirely. "
            "3. Firewall 2375/2376 so only the management host can reach them. "
            "4. Rotate any secrets/images that were reachable while the socket "
            "was open and review the engine for unexpected containers/images. "
            "Reference: https://docs.docker.com/engine/security/protect-access/"
        ),
    }


def rule_open_not_docker(s):
    if s.get("docker_unauth_hits"):
        return None
    if not s.get("docker_ran"):
        return None
    open_ports = s.get("docker_open_ports") or []
    if not open_ports:
        return None
    # An open port that did NOT yield a Docker /version JSON. Honest INFO -
    # we will not claim a Docker exposure we did not prove.
    return {
        "name": "Docker API port open but no Docker Engine response observed",
        "severity": "INFO",
        "cwe": "CWE-200",
        "evidence": (
            f"{s.get('docker_target', '?')} has TCP {open_ports} open but the "
            "endpoint did not return a recognizable Docker Engine /version "
            "payload. It may be another service on the same port, an mTLS "
            "endpoint, or a reverse proxy. No Docker exposure is asserted."
        ),
        "remediation": (
            "If this host is not meant to run a Docker remote API, confirm what "
            "service is bound to the port. If it is Docker behind a proxy / "
            "mTLS, ensure client-certificate enforcement is mandatory."
        ),
    }


def rule_protected(s):
    if s.get("docker_unauth_hits"):
        return None
    if not s.get("docker_ran"):
        return None
    protected = s.get("docker_tls_protected_ports") or []
    if not protected:
        return None
    return {
        "name": "Docker remote API endpoint enforces TLS/client-certificate access",
        "severity": "POSITIVE",
        "cwe": "CWE-306",
        "owasp": "A01:2021",
        "evidence": (
            f"{s.get('docker_target', '?')} TCP {protected} required a TLS "
            "handshake / client certificate or answered 401/403 -> the Docker "
            "remote API is access-controlled, not open. This is the secure "
            "configuration."
        ),
        "remediation": (
            "Keep mutual-TLS enforced and rotate the client certificates per "
            "your normal PKI lifecycle. Re-run after any dockerd config change."
        ),
    }


def rule_probe_error(s):
    if s.get("docker_unauth_hits"):
        return None
    if s.get("docker_open_ports") or s.get("docker_tls_protected_ports"):
        return None
    if s.get("docker_ran"):
        # Ran cleanly, nothing open -> emit a POSITIVE-style clean INFO.
        return {
            "name": "No exposed Docker remote API detected",
            "severity": "POSITIVE",
            "cwe": "CWE-306",
            "evidence": (
                f"{s.get('docker_target', '?')}: checked "
                f"{s.get('docker_ports_checked') or []} - no reachable Docker "
                "Engine remote API. The daemon is not exposed on these TCP ports."
            ),
            "remediation": (
                "Keep the Docker daemon bound to the local unix socket. If you "
                "later enable a TCP socket, require mutual-TLS and firewall it."
            ),
        }
    err = s.get("docker_no_target") and "no target supplied" or "probe did not run"
    return {
        "name": "Docker API exposure probe could not run",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": f"{s.get('docker_target', '?')}: {err}.",
        "remediation": (
            "Confirm the target host/IP is reachable from the scanner. If the "
            "engine is internal-only, run the scan from a host on the management "
            "network."
        ),
    }


DOCKER_API_EXPOSURE_PROBE_FINDING_RULES = [
    rule_docker_unauth_exposed,
    rule_open_not_docker,
    rule_protected,
    rule_probe_error,
]
