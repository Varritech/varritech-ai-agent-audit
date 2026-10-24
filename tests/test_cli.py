"""Smoke tests for the CLI entry point."""

from cli import main


def test_audit_help_exits_clean():
    # Just make sure --help doesn't crash
    try:
        rc = main(["--help"])
    except SystemExit as e:
        rc = e.code
    # argparse exits 0 on --help
    assert rc in (0, None)


def test_audit_in_tmp_dir(tmp_path):
    rc = main(["audit", str(tmp_path), "--format", "json"])
    assert rc == 0


def test_audit_ci_fails_on_high_threshold(tmp_path):
    # With a LOW risk score, --fail-on high should pass
    rc = main(["audit", str(tmp_path), "--ci", "--fail-on", "high"])
    assert rc == 0

def test_ci_fails_when_high_secret_in_history(tmp_git_repo):
    """A HIGH-severity secret in git history must fail the CI gate."""
    from pathlib import PurePath
    import subprocess

    (tmp_git_repo / "leaked.py").write_text(
        'AWS_ACCESS_KEY_ID = "AKIAREDACTEDNOTREAL0"\n', encoding="utf-8"
    )
    subprocess.check_call(
        ["git", "-C", str(tmp_git_repo), "add", "leaked.py"],
    )
    subprocess.check_call(
        ["git", "-C", str(tmp_git_repo), "commit", "-q", "-m", "leak"],
    )
    rc = main(["audit", str(tmp_git_repo), "--ci", "--fail-on", "high"])
    assert rc == 1
    del PurePath
