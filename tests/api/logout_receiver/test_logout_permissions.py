# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""Permission gating on the logout trigger need.

These tests check who may hold `trigger_logout_user`. Sync need gating lives
under `user_sync_service/user_update_service_permissions/`. HTTP auth on the
logout webhook lives under `test_inbound_webhook.py`. Static-token route
wiring lives under `api/auth_infrastructure/`.

Covers:

- SSO logout account may trigger logout.
- Profiles sync account may not trigger logout.
- `system_identity` retains the logout trigger need.

Related coverage elsewhere:

- Sync need gating →
  `user_sync_service/user_update_service_permissions/`.
- Central logout webhook behavior → `test_inbound_webhook.py`.
- Sync webhook HTTP wrong-account rejection →
  `on_webhook_sync_signal/test_user_webhook_auth.py`.
"""

import pytest
from invenio_access.permissions import system_identity
from invenio_records_resources.services.errors import PermissionDeniedError

from invenio_remote_user_data_kcworks.proxies import (
    current_remote_user_data_service as user_data_service,
)
from tests.fixtures.users import get_durable_service_user


def test_logout_capability_allows_logout(app, admin_roles):
    """SSO logout account may trigger logout."""
    _user, identity = get_durable_service_user("svc-commons-sso")
    user_data_service.require_permission(identity, "trigger_logout_user")


def test_sync_account_cannot_trigger_logout(app, admin_roles):
    """Profiles sync account may not trigger logout."""
    _user, identity = get_durable_service_user("svc-commons-profiles")
    with pytest.raises(PermissionDeniedError):
        user_data_service.require_permission(identity, "trigger_logout_user")


def test_system_identity_retains_logout_trigger(app):
    """Internal jobs using system_identity still pass the logout trigger check."""
    user_data_service.require_permission(system_identity, "trigger_logout_user")
