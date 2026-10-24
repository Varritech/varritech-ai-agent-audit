"""Repo audit tests — synthetic secrets in a fixture git repo."""

import subprocess

from scanner.repo_audit import scan_repo


# Synthetic fixtures, assembled at runtime so this repository contains no
# literal credential-shaped strings (GitHub push protection blocks those even
# when they are obviously fake). Each value below is pattern-valid, not real.
FAKE = {
    "aws_access_key_id": "AKIA" + "Q" * 16,
    "stripe_live_key": "sk_" + "live_" + "0" * 24,
    "openai_key": "sk-" + "T" * 40,
    "github_token": "ghp_" + "Z" * 36,
}

SECRETS_PY = "".join(
    f'{name.upper()} = "{value}"\n' for name, value in FAKE.items()
) + 'safe_value = "hello world"\n'



def _commit(repo, path, content):
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    subprocess.check_call(["git", "-C", str(repo), "add", path])
    subprocess.check_call(
        ["git", "-C", str(repo), "commit", "-q", "-m", f"add {path}"],
    )


def test_scan_repo_finds_aws_key(tmp_git_repo, config):
    _commit(tmp_git_repo, "secrets.py", SECRETS_PY)
    findings = scan_repo(tmp_git_repo, config)
    ids = {f.pattern_id for f in findings}
    assert "aws_access_key_id" in ids
    assert "stripe_live_key" in ids
    assert "openai_api_key" in ids
    assert "github_pat" in ids


def test_scan_repo_severity_ordering(tmp_git_repo, config):
    _commit(tmp_git_repo, "secrets.py", SECRETS_PY)
    findings = scan_repo(tmp_git_repo, config)
    severities = [f.severity for f in findings]
    # First finding should be high (severity-sorted)
    assert severities[0] == "high"


def test_scan_repo_ignores_test_fixtures(tmp_git_repo, config):
    # Create a file inside an ignored directory.
    (tmp_git_repo / "tests").mkdir()
    _commit(tmp_git_repo, "tests/fixtures/secrets.py", SECRETS_PY)
    findings = scan_repo(tmp_git_repo, config)
    assert findings == []


def test_scan_repo_empty_repo(tmp_git_repo, config):
    # Repo with no commits — should not error.
    findings = scan_repo(tmp_git_repo, config)
    assert findings == []


def test_scan_repo_no_git_dir(tmp_path, config):
    findings = scan_repo(tmp_path, config)
    assert findings == []