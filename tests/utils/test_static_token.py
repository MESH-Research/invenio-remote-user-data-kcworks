# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Unit tests for static-token route binding resolution."""

import pytest
from invenio_remote_user_data_kcworks.utils.static_token import (
    resolve_static_token_route,
)


def test_resolve_prefers_most_specific_prefix():
    routes = {
        "/webhooks": {"token_env": "A", "user_id_config": "UID_A"},
        "/webhooks/users/logout": {"token_env": "B", "user_id_config": "UID_B"},
        "/webhooks/users/update": {"token_env": "C", "user_id_config": "UID_C"},
    }
    config = {"UID_A": 1, "UID_B": 2, "UID_C": 3}
    binding = resolve_static_token_route(
        "/webhooks/users/logout?username=x", routes, config
    )
    assert binding is not None
    assert binding.token_env == "B"
    assert binding.user_id == 2


def test_resolve_string_entry_uses_legacy_user_id_key():
    routes = {"/webhooks/users/update": "COMMONS_PROFILES_API_TOKEN"}
    binding = resolve_static_token_route(
        "/webhooks/users/update",
        routes,
        {"STATIC_API_TOKEN_USER_ID": 99},
    )
    assert binding is not None
    assert binding.token_env == "COMMONS_PROFILES_API_TOKEN"
    assert binding.user_id == 99


def test_resolve_missing_user_id_returns_binding_with_none():
    routes = {
        "/webhooks/users/logout": {
            "token_env": "COMMONS_SSO_LOGOUT_API_TOKEN",
            "user_id_config": "STATIC_API_TOKEN_USER_ID_SSO",
        },
    }
    binding = resolve_static_token_route("/webhooks/users/logout", routes, {})
    assert binding is not None
    assert binding.token_env == "COMMONS_SSO_LOGOUT_API_TOKEN"
    assert binding.user_id is None


def test_resolve_rejects_bad_entry_type():
    with pytest.raises(TypeError):
        resolve_static_token_route(
            "/webhooks/users/update",
            {"/webhooks/users/update": 123},
            {},
        )
