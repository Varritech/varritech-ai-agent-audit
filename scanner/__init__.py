"""varritech-ai-agent-audit scanner library.

Modules:
    config         — load agents.yaml / secrets.yaml with sensible defaults
    process_audit  — find AI-coding-agent processes running locally
    network_audit  — list outbound connections from those processes
    repo_audit     — scan a git repo for likely-secret content in history
    report         — combine findings into a Markdown / JSON report
"""

from .config import load_config, AuditConfig
from .process_audit import scan_processes, ProcessFinding
from .network_audit import scan_egress, EgressFinding
from .repo_audit import scan_repo, RepoFinding
from .report import render_markdown, render_json, compute_risk_score

__all__ = [
    "load_config",
    "AuditConfig",
    "scan_processes",
    "ProcessFinding",
    "scan_egress",
    "EgressFinding",
    "scan_repo",
    "RepoFinding",
    "render_markdown",
    "render_json",
    "compute_risk_score",
]