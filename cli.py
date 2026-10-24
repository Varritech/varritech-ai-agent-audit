#!/usr/bin/env python3
"""vaia — Varritech AI Agent Audit CLI.

Usage:
    vaia audit [PATH]                Run the full audit on PATH (current dir if omitted)
    vaia scan-processes              Just the process check
    vaia scan-egress                 Just the network egress check
    vaia scan-repo [PATH]            Just the git-repo secret scan

Options:
    --format {markdown,json}         Output format (default: markdown)
    --out FILE                       Write report to FILE instead of stdout
    --ci                             CI mode: exit non-zero on HIGH risk
    --fail-on {low,medium,high}      Severity threshold for CI failure
    --agents-yaml FILE               Override path to agents.yaml
    --secrets-yaml FILE              Override path to secrets.yaml
    --config-dir DIR                 Directory containing the YAML configs
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
from pathlib import Path

# Make the scanner package importable when invoked directly from `scripts/`
sys.path.insert(0, str(Path(__file__).resolve().parent))

from scanner import (  # noqa: E402
    load_config,
    scan_processes,
    scan_egress,
    scan_repo,
    render_markdown,
    render_json,
    compute_risk_score,
)


def _host() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def _run_audit(args: argparse.Namespace) -> int:
    config = load_config(
        source_dir=args.config_dir,
        agents_file=args.agents_yaml,
        secrets_file=args.secrets_yaml,
    )
    scope = args.path or os.getcwd()
    scope_path = Path(scope).resolve()

    procs = scan_processes(config)
    egress = scan_egress(config, procs)
    repo = scan_repo(scope_path, config) if scope_path.exists() else []

    if args.format == "json":
        out = render_json(procs, egress, repo, scope=scope, host=_host())
    else:
        out = render_markdown(procs, egress, repo, scope=scope, host=_host())

    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
    else:
        print(out)

    # CI mode
    if args.ci:
        score = compute_risk_score(procs, egress, repo)
        rank = {"low": 1, "medium": 35, "high": 70}[args.fail_on]
        if score >= rank:
            print(
                f"\n[vaia] FAIL: risk score {score} >= threshold {args.fail_on}",
                file=sys.stderr,
            )
            return 1
        print(f"\n[vaia] OK: risk score {score} < threshold {args.fail_on}", file=sys.stderr)

    return 0


def _run_processes(args: argparse.Namespace) -> int:
    config = load_config(
        source_dir=args.config_dir,
        agents_file=args.agents_yaml,
        secrets_file=args.secrets_yaml,
    )
    procs = scan_processes(config)
    if args.format == "json":
        from dataclasses import asdict
        import json
        print(json.dumps([asdict(p) for p in procs], indent=2))
    else:
        for p in procs:
            mark = "[HIGH]" if p.risk_tier == "high" else "!"
            print(f"{mark} {p.matched_agent or p.name:<14} pid={p.pid:<6} {p.exe}")
    return 0


def _run_egress(args: argparse.Namespace) -> int:
    config = load_config(
        source_dir=args.config_dir,
        agents_file=args.agents_yaml,
        secrets_file=args.secrets_yaml,
    )
    procs = scan_processes(config)
    egress = scan_egress(config, procs)
    if args.format == "json":
        from dataclasses import asdict
        import json
        print(json.dumps([asdict(e) for e in egress], indent=2))
    else:
        for e in egress:
            mark = "[HIGH]" if e.status == "UNKNOWN" else "[ok]"
            print(f"{mark} {e.agent or '?':<14} {e.remote_host or e.remote_ip}:{e.remote_port}/{e.transport}  {e.status}")
    return 0


def _run_repo(args: argparse.Namespace) -> int:
    config = load_config(
        source_dir=args.config_dir,
        agents_file=args.agents_yaml,
        secrets_file=args.secrets_yaml,
    )
    target = args.path or os.getcwd()
    findings = scan_repo(target, config)
    if args.format == "json":
        from dataclasses import asdict
        import json
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        if not findings:
            print("No secrets found.")
        for f in findings:
            mark = "[HIGH]" if f.severity == "high" else "!"
            print(f"{mark} [{f.severity:<6}] {f.commit} {f.path:<40} {f.pattern_id}  {f.preview}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vaia",
        description="Audit the AI coding agents running on your machine.",
    )
    parser.add_argument("--config-dir", default=None)
    parser.add_argument("--agents-yaml", default=None)
    parser.add_argument("--secrets-yaml", default=None)
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--out", default=None)
    parser.add_argument("--ci", action="store_true")
    parser.add_argument("--fail-on", choices=["low", "medium", "high"], default="high")

    sub = parser.add_subparsers(dest="cmd", required=True)

    def _add_common(p: argparse.ArgumentParser) -> None:
        """Global flags are also accepted *after* the subcommand."""
        p.add_argument("--config-dir", default=argparse.SUPPRESS)
        p.add_argument("--agents-yaml", default=argparse.SUPPRESS)
        p.add_argument("--secrets-yaml", default=argparse.SUPPRESS)
        p.add_argument(
            "--format", choices=["markdown", "json"], default=argparse.SUPPRESS
        )
        p.add_argument("--out", default=argparse.SUPPRESS)
        p.add_argument("--ci", action="store_true", default=argparse.SUPPRESS)
        p.add_argument(
            "--fail-on",
            choices=["low", "medium", "high"],
            default=argparse.SUPPRESS,
        )

    p_audit = sub.add_parser("audit", help="Run the full audit")
    p_audit.add_argument("path", nargs="?", default=None)
    _add_common(p_audit)

    p_proc = sub.add_parser("scan-processes", help="Just the process check")
    _add_common(p_proc)

    p_egr = sub.add_parser("scan-egress", help="Just the network egress check")
    _add_common(p_egr)

    p_repo = sub.add_parser("scan-repo", help="Just the git-repo secret scan")
    p_repo.add_argument("path", nargs="?", default=None)
    _add_common(p_repo)

    args = parser.parse_args(argv)

    if args.cmd == "audit":
        return _run_audit(args)
    if args.cmd == "scan-processes":
        return _run_processes(args)
    if args.cmd == "scan-egress":
        return _run_egress(args)
    if args.cmd == "scan-repo":
        return _run_repo(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())