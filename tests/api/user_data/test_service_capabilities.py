# Part of Knowledge Commons Works
# Copyright (C) 2026, MESH Research
#
# KCWorks is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Capability isolation for Profiles sync vs SSO logout webhooks."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from flask import url_for
from flask_principal import Identity, identity_changed
from invenio_access.permissions import system_identity
from invenio_accounts.proxies import current_accounts
from invenio_records_resources.services.errors import PermissionDeniedError
from invenio_remote_user_data_kcworks.proxies import (
    current_remote_user_data_service,
)


def _identity_for_user(app, user) -> Identity:
    """Build a loaded identity for `user` (roles expanded)."""
    identity = Identity(user.id)
    identity_changed.send(app, identity=identity)
    return identity


@pytest.fixture
def sync_service_user(user_factory, db):
    """Non-admin user with users-sync + groups-sync only."""
    u = user_factory(
        email="svc-profiles@example.org",
        admin=False,
        token=False,
        oauth_src=None,
        oauth_id=None,
        kc_username=None,
    )
    datastore = current_accounts.datastore
    for role_name in ("users-sync", "groups-sync"):
        role = datastore.find_or_create_role(name=role_name)
        datastore.add_role_to_user(u.user, role)
    datastore.commit()
    return u


@pytest.fixture
def logout_service_user(user_factory, db):
    """Non-admin user with users-logout only."""
    u = user_factory(
        email="svc-sso@example.org",
        admin=False,
        token=False,
        oauth_src=None,
        oauth_id=None,
        kc_username=None,
    )
    datastore = current_accounts.datastore
    role = datastore.find_or_create_role(name="users-logout")
    datastore.add_role_to_user(u.user, role)
    datastore.commit()
    return u


def test_sync_capability_allows_users_sync_not_logout(app, sync_service_user):
    """Profiles sync account may trigger user sync but not logout."""
    identity = _identity_for_user(app, sync_service_user.user)
    current_remote_user_data_service.require_permission(
        identity, "trigger_users_sync"
    )
    current_remote_user_data_service.require_permission(
        identity, "trigger_groups_sync"
    )
    with pytest.raises(PermissionDeniedError):
        current_remote_user_data_service.require_permission(
            identity, "trigger_logout_user"
        )


def test_logout_capability_allows_logout_not_sync(app, logout_service_user):
    """SSO logout account may trigger logout but not user/group sync."""
    identity = _identity_for_user(app, logout_service_user.user)
    current_remote_user_data_service.require_permission(
        identity, "trigger_logout_user"
    )
    with pytest.raises(PermissionDeniedError):
        current_remote_user_data_service.require_permission(
            identity, "trigger_users_sync"
        )
    with pytest.raises(PermissionDeniedError):
        current_remote_user_data_service.require_permission(
            identity, "trigger_groups_sync"
        )


def test_system_identity_retains_all_triggers(app):
    """Internal jobs using system_identity still pass all trigger checks."""
    for action in (
        "trigger_users_sync",
        "trigger_groups_sync",
        "trigger_logout_user",
    ):
        current_remote_user_data_service.require_permission(system_identity, action)


def test_webhook_users_update_denied_for_logout_only_identity(
    app,
    client,
    headers,
    logout_service_user,
    monkeypatch,
):
    """Logout-only static principal cannot enqueue user sync webhooks."""
    monkeypatch.setenv("TEST_IDMS_STATIC_API_TOKEN", "logout-only-token")
    monkeypatch.setenv("COMMONS_PROFILES_API_TOKEN", "logout-only-token")
    app.config["STATIC_API_TOKEN_USER_ID"] = logout_service_user.user.id

    with (
        patch("invenio_remote_user_data_kcworks.views.do_user_data_update") as do_update,
        patch("invenio_accounts.utils.current_user"),
    ):
        url = url_for(
            "invenio_remote_user_data_kcworks.remote_user_data_kcworks_webhook",
        )
        resp = client.post(
            url,
            json={
                "idp": "knowledgeCommons",
                "updates": {"users": [{"id": "anyone", "event": "updated"}]},
            },
            headers={
                **headers,
                "Authorization": "Bearer logout-only-token",
            },
        )

    assert resp.status_code == 403
    do_update.delay.assert_not_called()
