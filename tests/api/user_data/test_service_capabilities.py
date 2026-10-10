# Part of Knowledge Commons Works
# Copyright (C) 2026, MESH Research
#
# KCWorks is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Capability isolation for Profiles sync vs SSO logout webhooks."""

from unittest.mock import patch

import pytest
from flask import url_for
from invenio_access.permissions import system_identity
from invenio_records_resources.services.errors import PermissionDeniedError
from invenio_remote_user_data_kcworks.proxies import (
    current_remote_user_data_service,
)
from tests.fixtures.users import get_durable_service_user


def test_sync_capability_allows_users_sync_not_logout(app, admin_roles):
    """Profiles sync account may trigger user sync but not logout."""
    _user, identity = get_durable_service_user("svc-commons-profiles")
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


def test_logout_capability_allows_logout_not_sync(app, admin_roles):
    """SSO logout account may trigger logout but not user/group sync."""
    _user, identity = get_durable_service_user("svc-commons-sso")
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
    admin_roles,
    monkeypatch,
):
    """Logout-only static principal cannot enqueue user sync webhooks."""
    user, _identity = get_durable_service_user("svc-commons-sso")
    monkeypatch.setenv("COMMONS_PROFILES_API_TOKEN", "logout-only-token")
    # Misconfigure the Profiles sync binding to the logout-only principal.
    app.config["STATIC_API_TOKEN_USER_ID_PROFILES"] = user.id

    update_patch = "invenio_remote_user_data_kcworks.views.do_user_data_update"
    with (
        patch(update_patch) as do_update,
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
