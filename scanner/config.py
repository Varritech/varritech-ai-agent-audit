"""Configuration loading for the audit tool.

The tool ships two YAML files (`agents.yaml`, `secrets.yaml`) next to this
module. They are loaded fresh on every CLI run so changes take effect
without reinstalling the package.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import yaml  # PyYAML
except ImportError:  # pragma: no cover - graceful degradation
    yaml = None  # type: ignore[assignment]


DEFAULT_DIR = Path(__file__).resolve().parent


@dataclass
class AuditConfig:
    """Combined runtime configuration for an audit run."""

    agents: list[dict[str, Any]]
    generic_ai_patterns: list[str]
    secret_patterns: list[dict[str, Any]]
    ignore_paths: list[str]
    source_dir: Path

    def find_agent(self, name: str) -> dict[str, Any] | None:
        for a in self.agents:
            if a.get("name") == name:
                return a
        return None


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    if yaml is not None:
        data = yaml.safe_load(text) or {}
    else:
        data = _minimal_yaml(text)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a YAML mapping at the top level")
    return data


def _minimal_yaml(text: str) -> dict[str, Any]:
    """Tiny fallback parser for the two config files this tool ships.

    Used only when PyYAML is unavailable. Supports the YAML subset these files
    use: nested mappings, block lists of scalars, block lists of flat mappings,
    and block scalars ("key: |") whose bodies are skipped. Anything else raises,
    so a user's override file is never silently mis-parsed.
    """
    result: dict[str, Any] = {}
    # indent -> container stack; the root mapping lives at indent 0 so that
    # top-level keys resolve their owner without a sentinel frame.
    stacks: dict[int, list[Any]] = {0: [result]}

    raw: list[tuple[int, str]] = []
    skip_deeper_than: int | None = None
    for ln in text.splitlines():
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        indent = len(ln) - len(ln.lstrip(" "))
        # Block scalars ("key: |", "key: >") are prose, not structure. Drop the
        # whole indented body; the key keeps the empty dict "(no value)" meaning.
        if skip_deeper_than is not None:
            if indent > skip_deeper_than:
                continue
            skip_deeper_than = None
        stripped = ln.strip()
        if stripped.endswith(("|", ">", "|-", ">-", "|+", ">+")):
            skip_deeper_than = indent
            key = stripped.rstrip("|>+-").strip()
            raw.append((indent, key if key.endswith(":") else key + ":"))
            continue
        raw.append((indent, stripped))

    for idx, (indent, line) in enumerate(raw):
        if line in ("---", "..."):
            continue
        for deeper in [d for d in stacks if d > indent and stacks[d]]:
            del stacks[deeper]

        frame = stacks.setdefault(indent, [])
        if not frame and indent == 0:
            frame = stacks[0] = [result]
        if not frame:
            owner_indent = max(d for d in stacks if d < indent)
            owner = stacks[owner_indent][-1]
            if isinstance(owner, list) and owner and isinstance(owner[-1], dict):
                # Still inside the last "- key: value" item.
                frame.append(owner[-1])
        if not frame:
            raise ValueError(f"unparseable YAML (bad indentation): {line!r}")
        parent = frame[-1]

        if line == "-" or line.startswith("- "):
            body = line[1:].strip()
            if not isinstance(parent, list):
                # The key above opened an empty dict; it is really a list.
                owner_indent = max(d for d in stacks if d < indent)
                owner = stacks[owner_indent][-1]
                if isinstance(owner, dict) and owner.values():
                    key = list(owner)[-1]
                    if isinstance(owner[key], dict) and not owner[key]:
                        owner[key] = []
                        frame[-1] = parent = owner[key]
                if not isinstance(parent, list):
                    raise ValueError(f"list item without a list: {line!r}")
            entry = _as_mapping_entry(body)
            if entry is None:
                parent.append(_scalar(body))
            else:
                key, value = entry
                item: dict[str, Any] = {key: value if value is not None else {}}
                parent.append(item)
                stacks[indent + 2] = [item]
                if value is None:
                    stacks[indent + 2] = [item[key]]
                else:
                    stacks[indent + 2] = [item]
            continue

        if ":" not in line:
            raise ValueError(f"unparseable YAML line: {line!r}")
        key, _, value = line.partition(":")
        key = key.strip().strip("\"'")
        value = value.strip()
        if not isinstance(parent, dict):
            raise ValueError(f"mapping entry inside a list needs nesting: {line!r}")
        if value != "":
            parent[key] = _scalar(value)
            continue
        # "key:" — decide dict vs list from the next line.
        nxt_indent, nxt_line = raw[idx + 1] if idx + 1 < len(raw) else (-1, "")
        is_list = (nxt_line == "-" or nxt_line.startswith("- ")) and nxt_indent > indent
        parent[key] = [] if is_list else {}
        stacks[indent + (2 if is_list else 1)] = [parent[key]]

    _fix_empty_lists(result)
    return result


def _as_mapping_entry(body: str) -> tuple[str, Any] | None:
    """'- key: value' -> (key, value); '- /path' or '- \"x\"' -> None."""
    if body[:1] in ("\"", "'"):
        return None
    if ": " not in body and not body.endswith(":"):
        return None
    key, _, rest = body.partition(":")
    key = key.strip().strip("\"'")
    rest = rest.strip()
    if not key or " " in key:
        return None
    return key, (_scalar(rest) if rest else None)


def _fix_empty_lists(node: Any) -> None:
    """A key with nothing under it is a list in these config files."""
    if isinstance(node, dict):
        for k, v in list(node.items()):
            if isinstance(v, dict) and not v:
                node[k] = []
            else:
                _fix_empty_lists(v)
    elif isinstance(node, list):
        for item in node:
            _fix_empty_lists(item)


def _scalar(value: str) -> Any:
    value = value.strip()
    if value.startswith("- ") and value.count(":") >= 1:
        inner = value[2:]
        key, _, rest = inner.partition(":")
        return {key.strip(): _scalar(rest)} if rest.strip() else {key.strip(): []}
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    lowered = value.lower()
    if lowered in ("true", "yes"):
        return True
    if lowered in ("false", "no"):
        return False
    if lowered in ("null", "~", ""):
        return None
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


def load_config(
    source_dir: str | os.PathLike[str] | None = None,
    agents_file: str | os.PathLike[str] | None = None,
    secrets_file: str | os.PathLike[str] | None = None,
) -> AuditConfig:
    """Load audit configuration from YAML files.

    Parameters
    ----------
    source_dir:
        Directory containing `agents.yaml` / `secrets.yaml`. Defaults to the
        directory next to this module.
    agents_file, secrets_file:
        Optional explicit overrides. If given as relative paths they are
        resolved relative to `source_dir`.
    """

    base = Path(source_dir).resolve() if source_dir else DEFAULT_DIR

    agents_path = Path(agents_file) if agents_file else base / "agents.yaml"
    secrets_path = Path(secrets_file) if secrets_file else base / "secrets.yaml"
    if not agents_path.is_absolute():
        agents_path = (base / agents_path).resolve()
    if not secrets_path.is_absolute():
        secrets_path = (base / secrets_path).resolve()

    agents_doc = _load_yaml(agents_path)
    secrets_doc = _load_yaml(secrets_path)

    return AuditConfig(
        agents=list(agents_doc.get("agents", [])),
        generic_ai_patterns=list(agents_doc.get("generic_ai_patterns", [])),
        secret_patterns=list(secrets_doc.get("patterns", [])),
        ignore_paths=list(secrets_doc.get("ignore_paths", [])),
        source_dir=base,
    )
