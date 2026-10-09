# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Helpers for resolving static bearer-token route bindings."""

from __future__ import annotations

from typing import Any, Mapping, NamedTuple


class StaticTokenRouteBinding(NamedTuple):
    """Token env var and impersonated user id for a matched static-token route."""

    token_env: str
    user_id: int | None


def _normalize_route_entry(entry: Any) -> tuple[str, str | None]:
    """Normalize a routes-map value to `(token_env, user_id_config)`.

    Args:
        entry: Either a token env-var name (str) or a mapping with
            `token_env` and optional `user_id_config`.

    Returns:
        Tuple of token env-var name and optional config key for the user id.

    Raises:
        TypeError: If `entry` is neither a string nor a mapping with
            `token_env`.
    """
    if isinstance(entry, str):
        return entry, None
    if isinstance(entry, Mapping):
        token_env = entry.get("token_env")
        if not isinstance(token_env, str) or not token_env:
            raise TypeError(
                "STATIC_API_TOKEN_ROUTES dict entries require a non-empty "
                "'token_env' string"
            )
        user_id_config = entry.get("user_id_config")
        if user_id_config is not None and not isinstance(user_id_config, str):
            raise TypeError(
                "STATIC_API_TOKEN_ROUTES 'user_id_config' must be a string "
                "config key when provided"
            )
        return token_env, user_id_config
    raise TypeError(
        "STATIC_API_TOKEN_ROUTES values must be a token env-var name or a "
        "dict with 'token_env'"
    )


def resolve_static_token_route(
    path: str,
    routes_map: Mapping[str, Any] | None,
    config: Mapping[str, Any],
) -> StaticTokenRouteBinding | None:
    """Resolve the static-token binding for a request path.

    Route map keys are path prefixes. The matching prefix with the most path
    segments wins. Values may be:

    - a string env-var name for the bearer token (user id from
      `STATIC_API_TOKEN_USER_ID`), or
    - a dict with `token_env` and optional `user_id_config` (config key
      holding the impersonated user id).

    Args:
        path: Request path as seen by the app.
        routes_map: `STATIC_API_TOKEN_ROUTES` mapping.
        config: Application config mapping.

    Returns:
        Binding for the most specific matching route, or `None`.
    """
    if not routes_map:
        return None

    matches: list[tuple[str, Any]] = [
        (prefix, entry)
        for prefix, entry in routes_map.items()
        if path.startswith(prefix)
    ]
    if not matches:
        return None

    most_specific = max(
        matches, key=lambda item: len([s for s in item[0].split("/") if s])
    )
    token_env, user_id_config = _normalize_route_entry(most_specific[1])
    config_key = user_id_config or "STATIC_API_TOKEN_USER_ID"
    user_id = config.get(config_key)
    if user_id is None:
        return StaticTokenRouteBinding(token_env=token_env, user_id=None)
    return StaticTokenRouteBinding(token_env=token_env, user_id=int(user_id))
