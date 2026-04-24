# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Generic nested-dictionary helpers."""

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
