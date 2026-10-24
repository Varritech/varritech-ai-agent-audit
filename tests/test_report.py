"""Risk-score + report rendering tests."""

from dataclasses import dataclass

from scanner.network_audit import EgressFinding
from scanner.process_audit import ProcessFinding
from scanner.repo_audit import RepoFinding
from scanner.report import compute_risk_score, render_markdown, render_json


def test_risk_score_zero_for_clean():
    score = compute_risk_score([], [], [])
    assert score == 0


def test_risk_score_high_for_zcode_egress():
    procs = [
        ProcessFinding(pid=1, name="zcode", exe="/ZCode", cmdline=[], matched_agent="zcode", risk_tier="high", closed_source=True),
    ]
    egress = [
        EgressFinding(pid=1, agent="zcode", remote_ip="1.2.3.4", remote_port=443, remote_host=None, status="UNKNOWN", transport="tcp", reason="not in allowlist"),
    ]
    score = compute_risk_score(procs, egress, [])
    assert score >= 32  # 20 (zcode) + 12 (unknown egress)


def test_risk_score_repo_finding_weights():
    repo = [
        RepoFinding(blob="abc12345", path="x.py", pattern_id="aws_access_key_id", severity="high", description="AWS key", preview="...AKIA...EXAMPLE..."),
        RepoFinding(blob="abc12345", path="x.py", pattern_id="stripe_test_key", severity="medium", description="Stripe test", preview="...sk_test_..."),
        RepoFinding(blob="abc12345", path="x.py", pattern_id="high_entropy_string", severity="low", description="entropy", preview="...abcd..."),
    ]
    score = compute_risk_score([], [], repo)
    # 10 + 4 + 1 = 15, lifted to the HIGH floor (70) by the leaked AWS key.
    assert score == 70


def test_risk_score_capped_at_100():
    procs = [
        ProcessFinding(pid=i, name="zcode", exe="", cmdline=[], matched_agent="zcode", risk_tier="high", closed_source=True)
        for i in range(20)
    ]
    score = compute_risk_score(procs, [], [])
    assert score == 100


def test_render_markdown_includes_risk_score():
    md = render_markdown([], [], [], scope=".")
    assert "RISK SCORE" in md
    assert "(LOW)" in md


def test_render_json_is_valid():
    import json
    js = render_json([], [], [], scope=".")
    data = json.loads(js)
    assert data["risk_score"] == 0
    assert data["risk_band"] == "LOW"

def test_high_secret_floors_the_score():
    """One HIGH-severity secret must reach the HIGH band on its own."""
    from scanner.repo_audit import RepoFinding
    from scanner.report import compute_risk_score

    finding = RepoFinding(
        blob="deadbeef",
        path="config.py",
        pattern_id="aws_access_key_id",
        severity="high",
        description="AWS Access Key ID",
        preview="...AKIA...",
    )
    assert compute_risk_score([], [], [finding]) >= 70
    del finding
