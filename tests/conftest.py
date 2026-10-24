"""Shared test fixtures."""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Make `scanner` importable when running `pytest` from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from scanner.config import load_config


@pytest.fixture(scope="session")
def config():
    return load_config()


@pytest.fixture
def tmp_git_repo(tmp_path):
    """Create a temp git repo with one commit so scan_repo can walk it.

    Uses the system `git` CLI (assumes it's on PATH, which it is on every
    dev machine and every CI image we'd run on).
    """

    import subprocess

    repo = tmp_path / "fixture-repo"
    repo.mkdir()
    subprocess.check_call(["git", "init", "-q", str(repo)])
    subprocess.check_call(
        ["git", "-C", str(repo), "config", "user.email", "test@example.com"],
    )
    subprocess.check_call(
        ["git", "-C", str(repo), "config", "user.name", "Test"],
    )
    return repo