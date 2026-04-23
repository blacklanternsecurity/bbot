"""
Deep-merge helpers replacing omegaconf's merge semantics.

`deep_update(a, b)` returns a new dict that is `a` with `b` merged in: nested
dicts are merged recursively, leaf values (and lists) from `b` replace those in
`a`. This matches `OmegaConf.merge(a, b)` for BBOT's preset layering use case.
"""

from __future__ import annotations

from typing import Any


def deep_update(base: dict[str, Any], *updates: dict[str, Any]) -> dict[str, Any]:
    """
    Deep-merge one or more update dicts into a copy of `base`. Last wins on
    leaf conflicts; lists are replaced wholesale (not concatenated).
    """
    result: dict[str, Any] = dict(base) if base else {}
    for update in updates:
        if not update:
            continue
        for k, v in update.items():
            if k in result and isinstance(result[k], dict) and isinstance(v, dict):
                result[k] = deep_update(result[k], v)
            else:
                result[k] = v
    return result


def dotted_get(data: dict[str, Any], path: str, default: Any = None) -> Any:
    """
    Look up a dotted path in a nested dict.

    >>> dotted_get({"a": {"b": {"c": 1}}}, "a.b.c")
    1
    >>> dotted_get({"a": 1}, "a.b.c", default="x")
    'x'
    """
    cursor: Any = data
    for part in path.split("."):
        if not isinstance(cursor, dict) or part not in cursor:
            return default
        cursor = cursor[part]
    return cursor


def dotted_set(data: dict[str, Any], path: str, value: Any) -> None:
    """
    Set a dotted path in a nested dict, creating intermediate dicts as needed.

    >>> d = {}
    >>> dotted_set(d, "a.b.c", 1)
    >>> d
    {'a': {'b': {'c': 1}}}
    """
    parts = path.split(".")
    cursor = data
    for part in parts[:-1]:
        if part not in cursor or not isinstance(cursor[part], dict):
            cursor[part] = {}
        cursor = cursor[part]
    cursor[parts[-1]] = value


def iter_dotted_paths(data: dict[str, Any], prefix: str = "") -> list[str]:
    """
    Yield every dotted leaf path in a nested dict.

    >>> iter_dotted_paths({"a": 1, "b": {"c": 2}})
    ['a', 'b.c']
    """
    paths: list[str] = []
    for k, v in data.items():
        path = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict) and v:
            paths.extend(iter_dotted_paths(v, path))
        else:
            paths.append(path)
    return paths


__all__ = ["deep_update", "dotted_get", "dotted_set", "iter_dotted_paths"]
