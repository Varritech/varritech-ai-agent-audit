# Runbook — wiring `varritech-ai-agent-audit` into CI

The tool exits non-zero when risk is high. That makes it drop-in for a CI
gate. The examples below show the three most common placements.

---

## GitHub Actions (PR gate)

Drop this into `.github/workflows/ai-agent-audit.yml`:

```yaml
name: AI Agent Audit
on:
  pull_request:
  push:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # full history so scan-repo can walk everything

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install
        run: |
          git clone https://github.com/Varritech/varritech-ai-agent-audit.git /tmp/vaia
          pip install /tmp/vaia

      - name: Run audit (fail on HIGH)
        run: vaia audit . --ci --fail-on high --out audit-report.md

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: ai-agent-audit-report
          path: audit-report.md
```

The job fails the PR if the audit reports HIGH risk. The Markdown report is
uploaded as a build artifact so reviewers can see exactly what triggered.

### Only run on protected branches

Add `if: github.event_name == 'pull_request'` to skip on direct pushes to
feature branches (where risk is by definition in flux).

---

## GitLab CI

```yaml
ai-agent-audit:
  image: python:3.11
  before_script:
    - pip install varritech-ai-agent-audit
  script:
    - vaia audit . --ci --fail-on high --out audit-report.md
  artifacts:
    when: always
    paths:
      - audit-report.md
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

---

## Pre-commit hook (local, fast)

For devs who want a check before they push:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Varritech/varritech-ai-agent-audit
    rev: v0.1.0
    hooks:
      - id: vaia-repo-scan
        name: AI agent audit (repo-only)
        entry: vaia scan-repo
        language: system
        pass_filenames: false
        types: [git]
```

The hook only runs the repo-secret scan — the process/network checks need
a live host and don't make sense as a pre-commit gate.

---

## Cron (host-level, weekly)

For a fleet audit, run on each dev laptop weekly via cron:

```cron
# Run the full audit every Monday at 09:00 local time, fail-fast on HIGH risk,
# email the report to security@ if it fails.
0 9 * * 1  /usr/local/bin/vaia audit /Users/$USER --ci --fail-on high --out /tmp/vaia-report.md || (mail -s "AI agent audit FAILED on $(hostname)" security@yourco.com < /tmp/vaia-report.md)
```

For a managed fleet, drop the audit into your MDM image as a launchd /
systemd timer that runs on login + every 24h.

---

## What to do when the audit fails

1. **HIGH egress to an unknown domain** → check the remote host (PTR + WHOIS
   + Shodan). If it's not a known vendor, block it at the firewall, then
   escalate to your security team. Treat the local host as potentially
   compromised until proven otherwise.
2. **HIGH-severity secret in `.git/` history** → rotate the credential
   immediately (treat it as compromised). Then `git filter-repo` to purge
   it, force-push, and notify anyone with a fork.
3. **Unknown AI agent process** → confirm with the user. If the agent is
   approved (e.g. on the allowlist in `agents.yaml`), add it. If not, kill
   the process and add the binary to the MDM blocklist.

---

## Integration with EDRs

The audit is **not** a replacement for an EDR. It's the cheap, fast,
*visible-to-developers* layer that catches the 90% case (a forgotten AI
agent, a leaked secret in a feature branch). For the long tail — lateral
movement, credential reuse, persistence — keep CrowdStrike / SentinelOne /
Defender for Endpoint in the loop and ship this tool's JSON output to your
SIEM via a small sidecar.

Example sidecar (pushes each audit run as a JSON line to Splunk HEC):

```python
# Splunk sidecar — save as /usr/local/bin/vaia-splunk-sidecar
import json, sys, requests, os
data = json.load(sys.stdin)
payload = {"event": data, "sourcetype": "vaia:audit"}
requests.post(
    os.environ["SPLUNK_HEC_URL"],
    headers={"Authorization": f'Splunk {os.environ["SPLUNK_HEC_TOKEN"]}'},
    json=payload,
    timeout=10,
)
```

Wire it up:

```bash
vaia audit . --format json --out - | vaia-splunk-sidecar
```