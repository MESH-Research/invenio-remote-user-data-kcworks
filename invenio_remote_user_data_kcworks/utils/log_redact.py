# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Helpers for keeping sensitive values out of application logs."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

_BEARER_RE = re.compile(r"(Bearer\s+)\S+", re.IGNORECASE)
_TOKENISH_JSON_RE = re.compile(
    r'("(?:access_token|refresh_token|token|password|secret|api_key)"\s*:\s*")[^"]*"',
    re.IGNORECASE,
)


def safe_body_snippet(text: str | None, max_len: int = 200) -> str:
    """Truncate and lightly redact common secret patterns in a body string.

    Args:
        text: Raw response or request body text.
        max_len: Maximum characters to retain after redaction.

    Returns:
        A log-safe snippet.
    """
    if not text:
        return ""
    redacted = _BEARER_RE.sub(r"\1[REDACTED]", text)
    redacted = _TOKENISH_JSON_RE.sub(r'\1[REDACTED]"', redacted)
    if len(redacted) <= max_len:
        return redacted
    return f"{redacted[:max_len]}..."


def mapping_keys_for_log(obj: Mapping[str, Any] | None) -> list[str]:
    """Return top-level keys for dict-like payloads (values omitted).

    Args:
        obj: Mapping whose keys may be logged.

    Returns:
        Sorted list of string keys, or an empty list.
    """
    if not obj:
        return []
    return sorted(str(k) for k in obj.keys())
