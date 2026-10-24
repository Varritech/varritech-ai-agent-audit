"""Process audit — list AI-coding-agent processes running on the host.

Cross-platform: uses psutil so it works on Linux, macOS, and WSL2. Doesn't
require root. Falls back gracefully if process command-line access is
restricted (e.g. macOS SIP on system processes).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore[assignment]

from .config import AuditConfig


# Provide a clear error message if scan_processes is called without psutil installed.
if psutil is None:  # pragma: no cover
    def _require_psutil_error():
        raise SystemExit(
            "psutil is required for the process audit. Install with: pip install psutil"
        )


@dataclass
class ProcessFinding:
    """One row in the process audit table."""

    pid: int
    name: str
    exe: str
    cmdline: list[str]
    matched_agent: str | None = None
    risk_tier: str = "unknown"
    closed_source: bool | None = None
    suspicious: bool = False
    reasons: list[str] = field(default_factory=list)


def _safe_cmdline(proc) -> list[str]:
    try:
        return proc.info.get("cmdline") or []
    except (psutil.AccessDenied, psutil.ZombieProcess):  # type: ignore[name-defined]
        return []


def _safe_exe(proc) -> str:
    try:
        return proc.info.get("exe") or ""
    except (psutil.AccessDenied, psutil.ZombieProcess):  # type: ignore[name-defined]
        return ""


def _iter_processes() -> Iterable:
    if psutil is None:
        return []
    attrs = ["pid", "name", "exe", "cmdline"]
    return psutil.process_iter(attrs=attrs, ad_value="")


def scan_processes(config: AuditConfig) -> list[ProcessFinding]:
    """Return a ProcessFinding for every AI-coding-agent process found.

    The audit considers two signals:
      1. Explicit match against `agents.yaml` binary patterns.
      2. Generic AI-pattern keyword match on the command line (e.g. "claude",
         "gpt", "agent"), which is then flagged as `suspicious=True` for manual
         review.
    """

    findings: list[ProcessFinding] = []

    if psutil is None:
        _require_psutil_error()  # pragma: no cover

    for proc in _iter_processes():
        exe = _safe_exe(proc) or ""
        cmdline = " ".join(_safe_cmdline(proc))
        haystack = " ".join([exe, cmdline, proc.info.get("name", "")]).lower()  # type: ignore[union-attr]

        matched_agent: dict | None = None
        for agent in config.agents:
            patterns = [p.lower() for p in agent.get("binary_patterns", [])]
            if any(p in haystack for p in patterns):
                matched_agent = agent
                break

        is_generic_match = False
        if matched_agent is None:
            is_generic_match = any(
                kw.lower() in haystack for kw in config.generic_ai_patterns
            )

        if matched_agent is None and not is_generic_match:
            continue

        reasons: list[str] = []
        suspicious = False
        if matched_agent is None:
            # Generic keyword match — flag as suspicious
            matched_name = None
            risk_tier = "unknown"
            closed = None
            suspicious = True
            reasons.append("Matched a generic AI keyword but is not in agents.yaml — manual review")
        else:
            matched_name = matched_agent.get("name")
            risk_tier = matched_agent.get("risk_tier", "unknown")
            closed = bool(matched_agent.get("closed_source"))
            if matched_agent.get("notes"):
                reasons.append(matched_agent["notes"].strip().splitlines()[0])
            if risk_tier == "high":
                reasons.append("Vendor has a documented abuse / opacity report")

        findings.append(
            ProcessFinding(
                pid=proc.info.get("pid"),  # type: ignore[union-attr]
                name=proc.info.get("name", ""),  # type: ignore[union-attr]
                exe=exe,
                cmdline=_safe_cmdline(proc),
                matched_agent=matched_name,
                risk_tier=risk_tier,
                closed_source=closed,
                suspicious=suspicious,
                reasons=reasons,
            )
        )

    # Sort: high risk first, then suspicious, then alphabetical
    severity_rank = {"high": 0, "medium": 1, "low": 2, "unknown": 3}
    findings.sort(
        key=lambda f: (
            severity_rank.get(f.risk_tier, 99),
            not f.suspicious,
            f.matched_agent or f.name,
        )
    )
    return findings