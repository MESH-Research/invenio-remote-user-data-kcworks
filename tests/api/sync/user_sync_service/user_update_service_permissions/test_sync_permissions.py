# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""Permission gating on the user-update / sync service needs.

These tests check who may hold `trigger_users_sync` / `trigger_groups_sync`,
and that `update_user_from_remote` refuses callers who lack permission before
any local lookup or Profiles fetch. HTTP credential and OAuth-scope checks on
the sync webhook live under `on_webhook_sync_signal/test_user_webhook_auth.py`.
Logout need gating lives under `logout_receiver/`. Static-token route wiring
lives under `api/auth_infrastructure/`.

Covers:

- Profiles sync account may trigger user/group sync.
- SSO logout account may not trigger user/group sync.
- `system_identity` retains the sync trigger needs.
- Missing permission is refused before any local lookup or remote fetch.

Related coverage elsewhere:

- Logout need gating → `logout_receiver/test_logout_permissions.py`.
- Sync webhook HTTP auth / wrong-account rejection →
  `on_webhook_sync_signal/test_user_webhook_auth.py`.
- Static-token path binding → `api/auth_infrastructure/test_static_token.py`.
"""

from unittest.mock import patch

import pytest
from invenio_access.permissions import system_identity
from invenio_records_resources.services.errors import PermissionDeniedError

from invenio_remote_user_data_kcworks.proxies import (
    current_remote_user_data_service as user_data_service,
)
from tests.fixtures.users import get_durable_service_user


def test_sync_capability_allows_users_and_groups_sync(app, admin_roles):
    """Profiles sync account may trigger user and group sync."""
    _user, identity = get_durable_service_user("svc-commons-profiles")
    user_data_service.require_permission(identity, "trigger_users_sync")
    user_data_service.require_permission(identity, "trigger_groups_sync")


def test_logout_account_cannot_trigger_sync(app, admin_roles):
    """SSO logout account may not trigger user or group sync."""
    _user, identity = get_durable_service_user("svc-commons-sso")
    with pytest.raises(PermissionDeniedError):
        user_data_service.require_permission(identity, "trigger_users_sync")
    with pytest.raises(PermissionDeniedError):
        user_data_service.require_permission(identity, "trigger_groups_sync")


def test_system_identity_retains_sync_triggers(app):
    """Internal jobs using system_identity still pass sync trigger checks."""
    for action in ("trigger_users_sync", "trigger_groups_sync"):
        user_data_service.require_permission(system_identity, action)


def test_update_user_from_remote_permission_denied(app):
    """Missing permission is refused before any local lookup or remote fetch."""
    with pytest.raises(PermissionDeniedError):
        with patch.object(
            user_data_service,
            "require_permission",
            side_effect=PermissionDeniedError(),
        ):
            user_data_service.update_user_from_remote(
                system_identity,
                999999,
                "knowledgeCommons",
                "sub-x",
            )
