# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Generic nested-dictionary helpers."""

from collections.abc import Callable, Iterable, Mapping
from typing import Any


def update_nested_dict(original: dict, update: dict) -> dict[str, Any]:
    """Recursively updates values in a nested dict based on an update dict.

    Returns:
        dict[str, Any]: The same `original` input dict mutated in place.
          During recursion leaf values may be any type.
    """
    for key, value in update.items():
        if isinstance(value, dict):
            original[key] = update_nested_dict(original.get(key, {}), value)
        elif isinstance(value, list):
            original.setdefault(key, []).extend(value)
        else:
            original[key] = value
    return original


def diff_between_nested_dicts(original, update):
    """Return the difference between two nested dictionaries.

    At present doesn't distinguish between additions and removals
    from lists
    """  # noqa
    diff = {}
    if not original:
        return update
    else:
        for key, value in update.items():
            if isinstance(value, dict):
                diff[key] = diff_between_nested_dicts(original.get(key, {}), value)
            elif isinstance(value, list):
                diff[key] = [i for i in value if i not in original.get(key, [])] + [
                    x for x in original.get(key, []) if x not in value
                ]
            else:
                if original.get(key) != value:
                    diff[key] = value
        diff = {k: v for k, v in diff.items() if v}
        return diff


def merge_dicts_first_wins(
    primary: Mapping[str, Any] | None,
    secondary: Mapping[str, Any] | None,
    *,
    exclude_from_secondary: Iterable[str] = (),
) -> dict[str, Any]:
    """Merge two flat dicts; `primary`'s values win on key collisions.

    Unlike `{**secondary, **primary}`, this also lets the caller drop
    selected keys from `secondary` entirely (useful when those keys
    carry provenance that is meaningless on the merged record).

    Args:
        primary: Preferred-source dict; its values are never overridden.
        secondary: Fallback-source dict; only contributes keys that
            `primary` does not already carry and that are not in
            `exclude_from_secondary`.
        exclude_from_secondary: Keys to drop from `secondary`
            entirely (treated as if absent).

    Returns:
        A new dict containing every `primary` entry plus any
        `secondary` entry whose key is not present in `primary` and
        not in `exclude_from_secondary`.
    """
    excluded = set(exclude_from_secondary)
    out: dict[str, Any] = {
        k: v for k, v in (secondary or {}).items() if k not in excluded
    }
    out.update(primary or {})
    return out


def union_dicts_by_key(
    primary: Iterable[Mapping[str, Any]] | None,
    secondary: Iterable[Mapping[str, Any]] | None,
    *,
    key: Callable[[Mapping[str, Any]], Any | None],
    canonicalize: Callable[[Mapping[str, Any]], dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Concatenate two iterables of dicts, dropping later items whose key collides.

    Items whose `key` returns `None` are skipped entirely (treated as
    invalid). `primary` entries appear first in the output, in their
    original order; `secondary` entries follow in their original order
    except for those whose key has already been seen.

    Args:
        primary: The preferred-source iterable. Entries appear first
            in the output.
        secondary: The fallback-source iterable.
        key: A function returning a hashable key for an entry, or
            `None` to skip that entry entirely.
        canonicalize: Optional per-entry transform applied before
            appending — useful when callers want the output entries
            stripped of extras or normalized to a canonical shape
            independent of the input shape. Defaults to a no-op
            (entries are appended as-is).

    Returns:
        A new list containing the union of the two inputs, deduped on
        `key` (first occurrence wins).
    """
    out: list[dict[str, Any]] = []
    seen: set[Any] = set()
    for src in (primary or (), secondary or ()):
        for item in src:
            k = key(item)
            if k is None:
                continue
            if k in seen:
                continue
            seen.add(k)
            out.append(canonicalize(item) if canonicalize is not None else dict(item))
    return out
