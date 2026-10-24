"""Config loading tests."""

from pathlib import Path

import pytest

from scanner.config import load_config


def test_load_default_config():
    cfg = load_config()
    assert cfg.agents, "agents.yaml should ship with at least one agent"
    assert any(a["name"] == "cursor" for a in cfg.agents)
    assert any(a["name"] == "zcode" for a in cfg.agents)


def test_load_explicit_dir(tmp_path):
    # Write a minimal agents.yaml in a temp dir
    (tmp_path / "agents.yaml").write_text(
        "agents:\n  - name: foo\n    binary_patterns: ['/foo/bar']\n    vendor_domains: ['api.foo.com']\n    risk_tier: low\n    closed_source: false\n",
        encoding="utf-8",
    )
    (tmp_path / "secrets.yaml").write_text(
        "patterns:\n  - id: dummy\n    regex: 'dummy_[a-z0-9]+'\n    severity: high\n    description: dummy\n",
        encoding="utf-8",
    )
    cfg = load_config(source_dir=tmp_path)
    assert len(cfg.agents) == 1
    assert cfg.agents[0]["name"] == "foo"
    assert cfg.secret_patterns[0]["id"] == "dummy"


def test_find_agent(config):
    zcode = config.find_agent("zcode")
    assert zcode is not None
    assert zcode["risk_tier"] == "high"
    assert zcode["closed_source"] is True


def test_missing_yaml_returns_empty(tmp_path):
    cfg = load_config(source_dir=tmp_path)
    assert cfg.agents == []
    assert cfg.secret_patterns == []
    assert cfg.ignore_paths == []

# --- fallback parser (PyYAML absent) ---------------------------------------
# The tool is usable on machines without PyYAML, so the minimal parser must
# handle the files it ships. These cover two regressions found in review:
#   1. top-level keys raised "bad indentation" (root frame was never found)
#   2. block scalars ("notes: |") were parsed as structure and raised

def _no_yaml():
    import scanner.config as cfg

    return cfg._minimal_yaml


def test_fallback_parses_top_level_keys():
    parse = _no_yaml()
    assert parse("version: 1") == {"version": 1}
    assert parse("a: 1\nb: 2") == {"a": 1, "b": 2}


def test_fallback_parses_nested_lists_of_mappings():
    parse = _no_yaml()
    got = parse(
        "k:\n"
        "  - name: x\n"
        "    v:\n"
        '      - "a.b"\n'
        "    t: medium\n"
        "z: 3\n"
    )
    assert got["k"][0]["name"] == "x"
    assert got["k"][0]["v"] == ["a.b"]
    assert got["k"][0]["t"] == "medium"
    assert got["z"] == 3


def test_fallback_skips_block_scalar_bodies():
    parse = _no_yaml()
    got = parse(
        "agents:\n"
        "  - name: zcode\n"
        "    notes: |\n"
        "      Sept 18 2026: vendor uploads .git/ with: a key only they hold\n"
        "      this line: must not be parsed\n"
        "    risk_tier: high\n"
    )
    assert got["agents"][0]["name"] == "zcode"
    assert got["agents"][0]["risk_tier"] == "high"
    assert "Sept 18 2026" not in str(got)


def test_shipped_agents_yaml_parses_without_pyyaml():
    """The bundled config must load with the fallback, not just with PyYAML."""
    from scanner.config import DEFAULT_DIR, _load_yaml

    doc = _load_yaml(DEFAULT_DIR / "agents.yaml")
    names = [a["name"] for a in doc["agents"]]
    assert "zcode" in names
    zcode = next(a for a in doc["agents"] if a["name"] == "zcode")
    assert zcode["risk_tier"] == "high"
