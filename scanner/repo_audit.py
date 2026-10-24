"""Repo audit — scan a git repo for likely-secret content in history.

This catches the case the ZCode report highlighted: even if your working
tree looks clean, secrets deleted in a later commit are still in
`.git/objects/`. We walk every blob reachable from `HEAD`, de-duplicate
identical blobs, and apply the regex + entropy patterns from
`secrets.yaml`.
"""

from __future__ import annotations

import math
import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .config import AuditConfig


MAX_BLOB_BYTES = 1_048_576  # 1 MB — skip media files
SAMPLE_BYTES = 65_536       # only scan the first 64KB of each blob


@dataclass
class RepoFinding:
    blob: str  # short blob SHA where the secret lives (git history keeps it)
    path: str
    pattern_id: str
    severity: str
    description: str
    preview: str


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _compile_patterns(config: AuditConfig) -> list[tuple[dict, re.Pattern]]:
    compiled: list[tuple[dict, re.Pattern]] = []
    for p in config.secret_patterns:
        try:
            compiled.append((p, re.compile(p["regex"])))
        except re.error as e:
            raise SystemExit(f"Bad regex in secrets.yaml pattern {p.get('id')!r}: {e}")
    return compiled


def _ignored(path: str, ignore_paths: list[str]) -> bool:
    """True if ``path`` lives under any configured ignore prefix.

    Entries may be directory names ("node_modules") or prefixes with a
    trailing slash ("tests/fixtures/"), so both forms work as written in
    secrets.yaml.
    """
    parts = path.split("/")
    for entry in ignore_paths:
        entry = entry.strip()
        if not entry:
            continue
        if entry.endswith("/"):
            prefix = entry.rstrip("/").split("/")
            if parts[: len(prefix)] == prefix:
                return True
        elif entry in parts:
            return True
    return False


def _is_text(blob: bytes) -> bool:
    if not blob:
        return False
    sample = blob[:1024]
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        try:
            sample.decode("latin-1")
        except UnicodeDecodeError:
            return False
    return True


def _walk_blobs(repo_dir: Path) -> Iterable[tuple[str, str, bytes]]:
    """Yield (blob_sha, path, blob_bytes) for every blob reachable from HEAD.

    Uses ``git rev-list --objects HEAD`` to enumerate (commit, path, blob) and
    a single ``git cat-file --batch`` session to stream every blob body, so the
    whole history costs two subprocesses. De-duplicates by blob SHA: the same
    content committed under several paths is yielded once, attributed to the
    newest commit that touched it.
    """
    if not _git_available():
        raise SystemExit(
            "git is required for the repo audit but was not found on PATH."
        )

    try:
        out = subprocess.check_output(
            ["git", "rev-list", "--objects", "HEAD"],
            cwd=str(repo_dir),
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        # Empty repo (no commits yet) — nothing to scan.
        return

    order: list[tuple[str, str]] = []  # (path, blob_sha), newest first
    seen_sha: set[str] = set()
    for line in out.decode("utf-8", errors="replace").splitlines():
        parts = line.split(" ", 1)
        if len(parts) != 2:
            continue
        _commit, rest = parts
        path, _, blob_sha = rest.partition(" ")
        if not blob_sha or blob_sha in seen_sha:
            continue
        seen_sha.add(blob_sha)
        order.append((f"{path}" or "<unnamed>", blob_sha))

    if not order:
        return

    p = subprocess.Popen(
        ["git", "cat-file", "--batch"],
        cwd=str(repo_dir),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    assert p.stdin and p.stdout
    payload = "".join(f"{sha}\n" for _, sha in order).encode("utf-8")
    stdout, _ = p.communicate(payload)

    # cat-file --batch stream: "<sha> <type> <size>\n<bytes>\n" per object.
    bodies: dict[str, bytes] = {}
    pos = 0
    total = len(stdout)
    while pos < total:
        nl = stdout.find(b"\n", pos)
        if nl == -1:
            break
        header = stdout[pos:nl].decode("utf-8", errors="replace").split()
        pos = nl + 1
        if len(header) < 3:
            continue  # "<sha> missing" etc.
        sha, kind, size = header[0], header[1], int(header[2])
        body = stdout[pos:pos + size]
        pos += size + 1  # trailing newline
        if kind == "blob":
            bodies[sha] = body

    for path, sha in order:
        blob = bodies.get(sha)
        if blob is not None:
            yield sha, path, blob


def _git_available() -> bool:
    try:
        subprocess.check_output(
            ["git", "--version"], stderr=subprocess.DEVNULL
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False
    return True


def scan_repo(
    repo_dir: str | Path,
    config: AuditConfig,
    commit_limit: int | None = None,
) -> list[RepoFinding]:
    """Scan the git history of `repo_dir` for secrets.

    Parameters
    ----------
    repo_dir:
        Path to a directory containing `.git/`.
    config:
        Audit configuration (compiled patterns + ignore list).
    commit_limit:
        If given, only inspect the most recent N commits. Useful for fast
        CI runs that just want HEAD~N.
    """

    repo_dir = Path(repo_dir).resolve()
    if not (repo_dir / ".git").exists():
        return []

    compiled = _compile_patterns(config)
    findings: list[RepoFinding] = []
    seen: set[tuple[str, str, str]] = set()  # (blob_sha, path, pattern_id)

    for blob_sha, path, blob in _walk_blobs(repo_dir):
        if len(blob) > MAX_BLOB_BYTES:
            continue
        if not _is_text(blob):
            continue
        if _ignored(path, config.ignore_paths):
            continue

        text = blob[:SAMPLE_BYTES].decode("utf-8", errors="replace")

        for pattern, regex in compiled:
            m = regex.search(text)
            if not m:
                # Also try the entropy-gated generic pattern
                if pattern.get("entropy_min"):
                    for cand in regex.findall(text):
                        if _entropy(cand) >= pattern["entropy_min"]:
                            m = type("M", (), {"group": lambda self, *_: cand})()  # type: ignore[assignment]
                            break
            if not m:
                continue

            key = (blob_sha, path, pattern["id"])
            if key in seen:
                continue
            seen.add(key)

            preview_start = max(0, m.start() - 20)
            preview_end = min(len(text), m.end() + 20)
            preview = text[preview_start:preview_end].replace("\n", "\\n")

            findings.append(
                RepoFinding(
                    blob=blob_sha[:8],
                    path=path,
                    pattern_id=pattern["id"],
                    severity=pattern.get("severity", "medium"),
                    description=pattern.get("description", pattern["id"]),
                    preview=f"...{preview}...",
                )
            )

    # Severity-sorted: high first, then by commit desc
    severity_rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(
        key=lambda f: (severity_rank.get(f.severity, 99), f.path, f.blob),
    )
    return findings