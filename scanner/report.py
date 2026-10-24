"""Render an audit run as Markdown or JSON."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Iterable

from .network_audit import EgressFinding
from .process_audit import ProcessFinding
from .repo_audit import RepoFinding


def compute_risk_score(
    processes: list[ProcessFinding],
    egress: list[EgressFinding],
    repo: list[RepoFinding],
) -> int:
    """Heuristic 0-100 risk score.

    - Each HIGH-risk agent process: +20
    - Each MEDIUM-risk agent process: +8
    - Each UNKNOWN-domain egress: +12
    - Each HIGH-severity repo finding: +10
    - Each MEDIUM-severity repo finding: +4
    - Each LOW-severity repo finding: +1

    A leaked HIGH-severity secret is always at least a HIGH score (70): a live
    AWS key in git history is a "drop everything" finding no matter how quiet
    the rest of the machine is. Capped at 100.
    """

    score = 0
    for p in processes:
        if p.risk_tier == "high":
            score += 20
        elif p.risk_tier == "medium":
            score += 8
        elif p.suspicious:
            score += 6
    for e in egress:
        if e.status == "UNKNOWN":
            score += 12
    high_secrets = 0
    for r in repo:
        if r.severity == "high":
            score += 10
            high_secrets += 1
        elif r.severity == "medium":
            score += 4
        elif r.severity == "low":
            score += 1
    if high_secrets:
        score = max(score, 70)
    return min(score, 100)


def _band(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def render_markdown(
    processes: list[ProcessFinding],
    egress: list[EgressFinding],
    repo: list[RepoFinding],
    scope: str,
    host: str = "unknown",
) -> str:
    score = compute_risk_score(processes, egress, repo)
    band = _band(score)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = []
    lines.append("# AI Coding Agent Audit Report")
    lines.append("")
    lines.append(f"- **Generated:** {ts}")
    lines.append(f"- **Host:** {host}")
    lines.append(f"- **Scope:** `{scope}`")
    lines.append("")
    lines.append(f"## RISK SCORE: {score} / 100 ({band})")
    lines.append("")

    # [1] Processes
    lines.append("## [1] Process audit")
    lines.append("")
    if not processes:
        lines.append("_No AI coding agent processes detected._")
        lines.append("")
    else:
        lines.append("| Status | Agent | PID | Executable | Notes |")
        lines.append("|--------|-------|-----|-----------|-------|")
        for p in processes:
            mark = "[HIGH]" if p.risk_tier == "high" else ("!" if p.suspicious or p.risk_tier == "medium" else "[ok]")
            agent = p.matched_agent or "_unknown_"
            exe = p.exe or " ".join(p.cmdline[:2])
            notes = "; ".join(p.reasons) or (f"closed_source={p.closed_source}" if p.closed_source is not None else "")
            lines.append(f"| {mark} | `{agent}` | {p.pid} | `{exe}` | {notes} |")
        lines.append("")

    # [2] Egress
    lines.append("## [2] Network egress audit")
    lines.append("")
    if not egress:
        lines.append("_No active outbound connections from identified AI agent processes._")
        lines.append("")
    else:
        lines.append("| Agent | Remote | Port | Status | Reason |")
        lines.append("|-------|--------|------|--------|--------|")
        for e in egress:
            mark = "[HIGH]" if e.status == "UNKNOWN" else "[ok]"
            remote = e.remote_host or e.remote_ip
            lines.append(
                f"| {mark} {e.agent or '?'} | `{remote}` | {e.remote_port}/{e.transport} | "
                f"{e.status} | {e.reason} |"
            )
        lines.append("")

    # [3] Repo
    lines.append("## [3] Repo risk audit")
    lines.append("")
    if not repo:
        lines.append("_No secrets found in scanned repo._")
        lines.append("")
    else:
        # Group by severity
        for sev, label in [("high", "HIGH-severity"), ("medium", "MEDIUM-severity"), ("low", "LOW-severity")]:
            subset = [r for r in repo if r.severity == sev]
            if not subset:
                continue
            lines.append(f"### {label} findings")
            lines.append("")
            lines.append("| Commit | Path | Pattern | Description | Preview |")
            lines.append("|--------|------|---------|-------------|---------|")
            for r in subset[:50]:  # cap output
                preview = r.preview.replace("|", "\\|")
                lines.append(
                    f"| `{r.blob}` | `{r.path}` | `{r.pattern_id}` | "
                    f"{r.description} | `{preview}` |"
                )
            lines.append("")
            if len(subset) > 50:
                lines.append(f"_…{len(subset) - 50} more matches omitted from this view; see JSON output for the full list._")
                lines.append("")

    # [4] Recommendations
    lines.append("## [4] Recommended actions")
    lines.append("")
    recs: list[str] = []
    n = 0
    def _next() -> int:
        nonlocal n
        n += 1
        return n
    if any(r.severity == "high" for r in repo):
        recs.append(f"{_next()}. **Rotate any HIGH-severity secrets** flagged above immediately — they're in `.git/` history and may already be in third-party archives.")
    if any(r.severity == "medium" for r in repo):
        recs.append(f"{_next()}. Audit MEDIUM-severity findings (Stripe test keys, DB URLs) before they ship.")
    if any(e.status == "UNKNOWN" for e in egress):
        unknowns = sorted({e.remote_host or e.remote_ip for e in egress if e.status == "UNKNOWN"})
        recs.append(f"{_next()}. Investigate outbound connections to **{', '.join(unknowns)}** — these are not in any vendor allowlist.")
    if any(p.risk_tier == "high" for p in processes):
        high_agents = sorted({p.matched_agent or p.name for p in processes if p.risk_tier == "high"})
        recs.append(f"{_next()}. Treat {', '.join(high_agents)} as untrusted until the vendor publishes a transparency report. Consider uninstalling or sandboxing.")
    if any(p.suspicious for p in processes):
        suspicious = sorted({p.name for p in processes if p.suspicious})
        recs.append(f"{_next()}. Review generic-AI-keyword processes manually: {', '.join(suspicious)}.")
    if not recs:
        recs.append("- All clear. Keep running this audit in CI on every PR.")
    lines.extend(recs)
    lines.append("")
    return "\n".join(lines)


def render_json(
    processes: list[ProcessFinding],
    egress: list[EgressFinding],
    repo: list[RepoFinding],
    scope: str,
    host: str = "unknown",
) -> str:
    score = compute_risk_score(processes, egress, repo)
    payload = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "host": host,
        "scope": scope,
        "risk_score": score,
        "risk_band": _band(score),
        "processes": [asdict(p) for p in processes],
        "egress": [asdict(e) for e in egress],
        "repo_findings": [asdict(r) for r in repo],
    }
    return json.dumps(payload, indent=2, default=str)