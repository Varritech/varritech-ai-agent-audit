"""Network egress audit — list outbound connections from AI agent processes.

Approach: we don't run a packet capture (that needs root and is noisy). We
read psutil's view of currently-open TCP/UDP connections and filter to those
owned by PIDs we identified as AI agents in `process_audit`.

This catches the case where the agent has a *live* connection out. For
historical forensic capture, pair this with a DNS log shipper (Pi-hole,
NextDNS) or an EDR — that's out of scope here.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore[assignment]

from .config import AuditConfig
from .process_audit import ProcessFinding


@dataclass
class EgressFinding:
    pid: int
    agent: str | None
    remote_ip: str
    remote_port: int
    remote_host: str | None  # resolved hostname if available
    status: str  # "ALLOWLIST" | "UNKNOWN" | "BLOCKED"
    transport: str  # "tcp" | "udp"
    reason: str


def _allowlist_domains(config: AuditConfig) -> set[str]:
    domains: set[str] = set()
    for agent in config.agents:
        for d in agent.get("vendor_domains", []):
            domains.add(d.lower())
    return domains


def _match_allowlist(host_lower: str, allowlist: set[str]) -> str | None:
    """Return the allowlisted domain that matches `host_lower`, or None.

    Suffix match — e.g. allowlist entry `aliyuncs.com` matches
    `zcode-oss-cn-shanghai.aliyuncs.com`. This is intentional for the
    ZCode case; if you'd rather do exact-match only, change this to `==`.
    """

    for d in allowlist:
        if host_lower == d or host_lower.endswith("." + d):
            return d
    return None


def _resolve_ptr(ip: str) -> str | None:
    """Best-effort reverse DNS. Returns None on failure or timeout."""

    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None


def _iter_connections_for_pids(pids: Iterable[int]):
    if psutil is None:
        return
    pids_set = set(pids)
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.pid is None or conn.pid not in pids_set:
                continue
            yield conn
    except psutil.AccessDenied:  # type: ignore[name-defined]
        # macOS without root, etc. — degrade to empty.
        return


def scan_egress(
    config: AuditConfig,
    processes: list[ProcessFinding],
) -> list[EgressFinding]:
    findings: list[EgressFinding] = []

    if not processes:
        return findings

    allowlist = _allowlist_domains(config)
    agent_by_pid: dict[int, str] = {p.pid: (p.matched_agent or p.name) for p in processes}

    seen: set[tuple[int, str, int, str]] = set()
    for conn in _iter_connections_for_pids(agent_by_pid.keys()):
        if conn.raddr is None:
            continue
        ip, port = conn.raddr.address, conn.raddr.port
        # Skip local / link-local targets — not interesting for an exfil audit
        if ip.startswith("127.") or ip.startswith("::1") or ip.startswith("0.0.0.0"):
            continue
        transport = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
        key = (conn.pid, ip, port, transport)
        if key in seen:
            continue
        seen.add(key)

        host = _resolve_ptr(ip)
        host_lower = (host or ip).lower()

        match = _match_allowlist(host_lower, allowlist)
        if match:
            status = "ALLOWLIST"
            reason = f"vendor domain ({match})"
        else:
            status = "UNKNOWN"
            reason = "not in any allowlisted vendor domain"

        findings.append(
            EgressFinding(
                pid=conn.pid,
                agent=agent_by_pid.get(conn.pid),
                remote_ip=ip,
                remote_port=port,
                remote_host=host,
                status=status,
                transport=transport,
                reason=reason,
            )
        )

    # Most suspicious first
    findings.sort(key=lambda f: (0 if f.status == "UNKNOWN" else 1, f.remote_host or f.remote_ip))
    return findings


def parse_url_host(url: str) -> str:
    """Helper used by tests. `urlparse('http://api.openai.com').hostname`."""

    return (urlparse(url).hostname or "").lower()