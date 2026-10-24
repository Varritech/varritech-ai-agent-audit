# varritech-ai-agent-audit

**Audit the AI coding agents running on your machine — before they leak your repo.**

A 30-second local audit that checks:

1. **Which AI agents are running** on your machine (Cursor, Continue, Aider, ZCode, Cline, Cody, Windsurf, Claude Code, …)
2. **Where they're talking to** — outbound connections from those processes, against an allowlist of known-vendor domains
3. **What your repo is leaking** — high-entropy strings, AWS/Stripe/GitHub/OpenAI keys, `.env` artifacts in `.git/` history
4. **A single risk score** + a Markdown / JSON report you can attach to a PR or share with security

Inspired by the **September 18, 2026 disclosure** that ZCode (Z.ai's desktop AI
coding app) silently packaged full `.git/` histories, encrypted them with a key
only the vendor could use, and uploaded them to Alibaba Cloud OSS — covering
years of repo history including deleted API keys, unreleased branch names, and
internal hostnames. (Original report by ferstar; 276K+ views in hours.)

> **You don't have to use a closed-source AI agent to be safe. You just have to
> know which ones are doing what on your laptop.**

---

## Why this exists

Every dev team adopting AI coding agents now has the same blind spot:

- "Cursor is on my machine, but is it phoning home?"
- "We approved Aider for engineers. Is anyone running Cline too?"
- "I deleted that AWS key 3 months ago. Is it still in `.git/objects/`?"

The headlines say *one* vendor was caught. The actual risk surface is every
closed-source AI harness your team has installed, signed in to, and forgotten
about. This tool turns that into a 30-second check you can run in CI.

---

## Quick Start (3 commands)

```bash
# 1. Clone and install
git clone https://github.com/Varritech/varritech-ai-agent-audit.git
cd varritech-ai-agent-audit
pip install -e .

# 2. Run the full audit on the current directory
vaia audit .

# 3. Read the report
cat audit-report.md
```

That's it. No daemon, no cloud calls, no telemetry. The tool only reads
process state and your filesystem; it never sends anything off-host.

---

## What's included

| Path | What it is |
|------|------------|
| `scanner/` | The audit library — process, network, repo, and report modules |
| `cli.py` | CLI entry point (`vaia audit`, `vaia scan-processes`, …) |
| `scanner/agents.yaml` | Allowlist of known AI coding agent binaries + vendor domains |
| `scanner/secrets.yaml` | Regex patterns for high-risk strings (AWS, Stripe, OpenAI, GitHub PATs, …) |
| `docs/audit-methodology.md` | How each check works, false-positive notes, and how to extend |
| `docs/runbook.md` | How to wire this into CI (GitHub Actions example included) |
| `tests/` | Unit tests + a fixture `.git` with synthetic secrets |

---

## What the report looks like

```
AI Coding Agent Audit Report
============================
Generated: 2026-09-18 15:04 UTC
Host:      macbook-pro-17 (Darwin 24.6.0)
Scope:     /Users/dev/code/payments-svc

RISK SCORE: 72 / 100  (HIGH)

[1] Process audit
    ✓ cursor          /Applications/Cursor.app/Contents/MacOS/Cursor   (signed in)
    ! cline           ~/.vscode/extensions/saoudrizwan.claude-dev-3.4.1/bin/cline   (signed in)
    ! zcode           ~/Applications/ZCode.app/Contents/MacOS/zcode   (closed source, no allowlist entry)

[2] Network egress audit
    cursor → api.cursor.sh                  ALLOWLIST   (vendor API)
    cursor → telemetry.cursor.sh             ALLOWLIST   (telemetry)
    cline  → api.anthropic.com              ALLOWLIST   (vendor API)
    cline  → api.openai.com                 ALLOWLIST   (vendor API)
    zcode  → zcode-oss-cn-shanghai.aliyuncs.com   UNKNOWN  🚨
    zcode  → metrics-zai-z1.z.ai            UNKNOWN  🚨

[3] Repo risk audit
    Repo: /Users/dev/code/payments-svc
    Commits scanned: 1,847
    High-entropy blobs: 23
    Matches:
      • commit 7f3a91c  AWS Access Key ID   (AKIA…4ZQ)            SECRET
      • commit 1ee22a0  Stripe live key     (sk_live_…Mx3)        SECRET
      • commit 9c001be  GitHub PAT          (ghp_…aP1)             SECRET
    Note: secrets are in `.git/objects/` even though the working tree is clean.

[4] Recommended actions
    1. Rotate the AWS, Stripe, and GitHub credentials above NOW.
    2. Add `zcode-oss-cn-shanghai.aliyuncs.com` and `*.z.ai` to your deny list
       or uninstall ZCode until the vendor publishes a transparency report.
    3. Purge secrets from git history (git-filter-repo + force-push + key rotation).
    4. Block the `zcode` process from launching on this machine (mdm / osquery).
```

---

## Usage

```bash
# Full audit on the current directory
vaia audit .

# Just the process check
vaia scan-processes

# Just the network egress check (Linux: reads /proc/net/tcp; macOS: uses `lsof`)
vaia scan-egress

# Just the repo-secret scan (pass any git repo path)
vaia scan-repo /path/to/repo

# Output as JSON instead of Markdown
vaia audit . --format json --out audit-report.json

# CI mode — non-zero exit code if any HIGH severity finding
# (flags work before or after the subcommand)
vaia audit . --ci --fail-on high
```

---

## Requirements

- Python 3.10+
- `psutil` (process listing + connections)
- `git` CLI on `PATH` (only for `scan-repo` — uses `git rev-list` + `git cat-file`)
- `PyYAML` is optional: if it is missing the tool falls back to a built-in
  parser that handles the shipped config files (nested mappings, block lists,
  block scalars such as `notes: |`), and says nothing about it
- Linux, macOS, or WSL2. The network-egress check degrades gracefully on each
  platform (see `docs/audit-methodology.md`).

Install:
```bash
pip install -r requirements.txt
# or
pip install -e .
```

---

## Cost

Free. No cloud calls. The tool reads local state only.

| Method | Setup | Per-run cost | Notes |
|--------|-------|--------------|-------|
| Manual review (1 dev, ~30 min/repo) | 0 | ~$25 in time | Easy to miss closed-source binaries |
| EDR/SIEM (CrowdStrike + Splunk) | enterprise | $5K–$50K/yr | Overkill for most startups |
| **`varritech-ai-agent-audit`** | 1 pip install | $0 | One-shot audit, CI-friendly, 30s/run |

---

## Extending it

Add a new AI agent to the allowlist — `scanner/agents.yaml`:

```yaml
agents:
  - name: my-cool-agent
    binary_patterns:
      - "/opt/my-cool-agent/bin/agent"
    vendor_domains:
      - "api.my-cool-agent.com"
    risk_tier: medium   # low | medium | high
    closed_source: true
```

Add a new secret regex — `scanner/secrets.yaml`:

```yaml
patterns:
  - id: my_custom_token
    regex: 'mc_[A-Za-z0-9]{32}'
    severity: high
```

Both files are re-read on every run — no rebuild needed.

---

## Limitations

The risk score floors at **70 (HIGH)** whenever a HIGH-severity secret is found
in git history — a live AWS key in `.git/objects/` is a drop-everything finding
regardless of how quiet the rest of the machine is. That means
`--ci --fail-on high` really does block a PR over a leaked key.

This is a **point-in-time audit**, not a network IDS. It will:

- Tells you what *was* running and what *was* on the wire the moment you ran it.
- Does not catch an agent that uploaded your repo at 3 AM and has since exited.

For continuous monitoring, wire it into CI (`docs/runbook.md`) and pair with an
endpoint-side egress monitor (e.g. a NextDNS log + a Zeek sensor).

---

## License

MIT — see `LICENSE`.

---

## Maintainer

Varritech — building AI systems you can actually audit.
This tool came out of a real audit we ran on a customer's dev fleet in
September 2026. If it saved you a leak, we'd love to hear about it
(christian@varritech.com).