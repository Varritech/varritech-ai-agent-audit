# Audit methodology

What each check does, what it can miss, and how to extend it.

---

## 1. Process audit (`scan_processes`)

**What it does.** Walks every PID on the host via `psutil.process_iter`, reads
`exe` + `cmdline`, and matches them against `scanner/agents.yaml`.

**Match logic.**
1. For each known agent, lowercase-substring match any `binary_patterns`
   entry against the combined `exe + cmdline + name` haystack.
2. If nothing matches, look for generic AI keywords (`claude`, `gpt`, `agent`,
   `copilot`, `chat`, `llm`) — these are flagged as `suspicious=True` for
   manual review rather than auto-attributed to an agent.

**What it can miss.**
- Agents that are launched ephemerally (e.g. via a shell one-liner) and have
  already exited by the time you run the audit.
- Agents running inside a container — `psutil` only sees PIDs in the current
  mount namespace. Run the audit inside the container, or `docker exec` into
  it.
- Agents that disguise their binary name. Mitigate by adding process-name
  fingerprints (e.g. via the command line flag your team uses).

**False positives.**
- A developer running `claude` in a shell will match the generic AI keyword.
  The CLI flags it as suspicious so you can confirm.
- `agent` is a common substring of unrelated programs. If you have
  `software-agent`, `newrelic-agent`, etc. on the host, expect them to match.

**Performance.** O(P) where P is the number of processes on the host
(typically < 500). One pass, no subprocesses.

---

## 2. Network egress audit (`scan_egress`)

**What it does.** Calls `psutil.net_connections(kind="inet")` to enumerate
open TCP/UDP sockets, filters to those owned by AI-agent PIDs identified in
step 1, and classifies each remote as `ALLOWLIST` (matches a `vendor_domains`
entry from `agents.yaml`) or `UNKNOWN`.

**Match logic.** Suffix match. An allowlist entry of `aliyuncs.com` matches
`zcode-oss-cn-shanghai.aliyuncs.com`. This is intentional — the ZCode
disclosure showed uploads going to Alibaba Cloud OSS in general.

**What it can miss.**
- **Past** uploads. If the agent already finished its exfiltration at 3 AM
  and the socket has since been torn down, you'll see nothing. Pair this tool
  with a DNS log shipper (Pi-hole, NextDNS) or an EDR for historical
  forensic capture.
- TLS SNI is not decrypted. Reverse DNS is best-effort and may not resolve
  for CDNs. If you need to see the actual hostname the agent connected to,
  use a TLS-terminating proxy like mitmproxy.
- Local-only connections (localhost, link-local) are filtered out — those
  are not interesting for an exfil audit.

**False positives.**
- CDNs serve many tenants on the same IP. An IP in `cf-rum.cloudflare.com`
  could be either your analytics endpoint or a rogue exfil channel. Use the
  host's PTR record, not the IP, when classifying.

**Performance.** O(C) where C is the number of open sockets on the host
(typically 100–2,000). Reverse DNS adds latency — capped by the OS's own
timeouts.

---

## 3. Repo audit (`scan_repo`)

**What it does.** Walks every blob reachable from `HEAD` via `git rev-list
--objects` + `git cat-file`. Deduplicates by blob SHA so the same content
under multiple paths doesn't multiply findings. Applies each regex from
`scanner/secrets.yaml`; for the generic high-entropy pattern, only flags
strings whose Shannon entropy exceeds the configured threshold.

**Why `.git/`?** This is the part most teams miss. Even if your working tree
is clean, secrets *deleted in a later commit* are still in `.git/objects/`
as garbage-collectible loose objects. The ZCode disclosure is a reminder:
the `56.8%` of the encrypted payload that was `.git/lfs/` and the `29.6%`
that was `.git/objects/` were the most damaging parts.

**What it can miss.**
- Blobs > 1 MB are skipped (media, large compiled artifacts). If you ever
  committed a binary with secrets in it, the audit won't catch them.
- Only the first 64 KB of each blob is scanned. Secrets past that offset
  are missed.
- `git filter-repo`'d repos look clean to us, which is what you want.
- Repos that *aren't* git repos. The audit silently returns no findings.

**False positives.**
- The high-entropy pattern will flag long random-looking base64 strings
  (think: image data in CSS, JWTs, content hashes). Triage by `pattern_id`.
- Test fixtures. Add `fixtures/secrets/` to `ignore_paths` if you maintain
  a test corpus.

**Performance.** O(B × P) where B is unique blobs and P is patterns. For a
medium repo (1,000 commits, ~5,000 unique blobs), this finishes in 5–20
seconds on a modern laptop. The first run is the slowest; subsequent runs
reuse the git object cache.

---

## Risk score

| Signal | Weight |
|--------|--------|
| Each HIGH-risk agent process | +20 |
| Each MEDIUM-risk agent process | +8 |
| Each suspicious (generic-keyword) process | +6 |
| Each UNKNOWN-domain egress | +12 |
| Each HIGH-severity repo finding | +10 |
| Each MEDIUM-severity repo finding | +4 |
| Each LOW-severity repo finding | +1 |

Capped at 100. Bands: `LOW < 35 ≤ MEDIUM < 70 ≤ HIGH`.

The score is a heuristic. Don't optimise for the number; optimise for
*zero unknown egresses and zero high-severity repo findings*.

---

## Extending

### Add a new AI agent

```yaml
# scanner/agents.yaml
agents:
  - name: my-cool-agent
    display_name: My Cool Agent
    binary_patterns:
      - "/opt/my-cool-agent/bin/agent"
      - "my-cool-agent"
    vendor_domains:
      - "api.my-cool-agent.com"
    risk_tier: medium      # low | medium | high
    closed_source: false
```

Re-run. The CLI re-reads the YAML on every invocation.

### Add a new secret pattern

```yaml
# scanner/secrets.yaml
patterns:
  - id: my_custom_token
    regex: 'mc_[A-Za-z0-9]{32}'
    severity: high
    description: My Cool Service token
```

### Wire into CI

See `docs/runbook.md` for a GitHub Actions example that fails the build on
HIGH risk.

---

## Limitations, in one line

This is a *point-in-time* audit of the local host. Pair it with continuous
DNS logging and an EDR for the historical view; pair it with a SOC2-style
vendor review for the policy view.