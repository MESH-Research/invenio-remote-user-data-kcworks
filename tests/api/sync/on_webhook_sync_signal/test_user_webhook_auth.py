# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Endpoint auth for the Profiles sync webhook (GET ping and POST).

Covers:

- GET with valid sync credentials succeeds (“receiver is active”).
- GET without credentials → HTTP 401; no job queued.
- POST without credentials → HTTP 401; no job queued.
- Profiles sync account token missing `webhooks:user-data` → HTTP 403; no job.
- Admin token missing `webhooks:user-data` → HTTP 403; no job
  (admin capability does not bypass the scope check).
- Token that includes `webhooks:user-data` → HTTP 202; job queued.
- Logout-only static principal on the sync endpoint → HTTP 403; no job.

Service need gating (who may hold `trigger_users_sync`) →
`user_sync_service/user_update_service_permissions/`.
Static-token path binding → `api/auth_infrastructure/test_static_token.py`.
"""

from unittest.mock import patch

from flask import url_for
from invenio_oauth2server.models import Token

from tests.fixtures.users import get_durable_service_user

_DO_USER_CREATED = "invenio_remote_user_data_kcworks.views.do_user_created"
_DO_USER_UPDATE = "invenio_remote_user_data_kcworks.views.do_user_data_update"
_WEBHOOK_ENDPOINT = (
    "invenio_remote_user_data_kcworks.remote_user_data_kcworks_webhook"
)
_SYNC_SCOPE = "webhooks:user-data"
_WRONG_SCOPE = "webhooks:logout"


def test_webhook_get_with_valid_credentials_succeeds(
    app, client, idms_static_api_auth
):
    """Authenticated GET confirms the sync webhook receiver is active."""
    with app.app_context():
        url = url_for(_WEBHOOK_ENDPOINT)
    resp = client.get(url, headers=idms_static_api_auth)
    assert resp.status_code == 200
    assert resp.json == {
        "message": "Webhook receiver is active",
        "status": 200,
    }


def test_webhook_get_without_credentials_is_rejected(app, client):
    """GET without Authorization is rejected."""
    with app.app_context():
        url = url_for(_WEBHOOK_ENDPOINT)
    resp = client.get(url)
    assert resp.status_code == 401


def test_webhook_post_without_credentials_is_rejected(app, client, headers):
    """POST without Authorization is rejected."""
    with app.app_context():
        url = url_for(_WEBHOOK_ENDPOINT)
    with patch(_DO_USER_UPDATE) as do_update:
        resp = client.post(
            url,
            json={
                "idp": "knowledgeCommons",
                "updates": {
                    "users": [{"id": "anyone", "event": "updated"}],
                },
            },
            headers=headers,
        )

    assert resp.status_code == 401
    do_update.delay.assert_not_called()


def test_webhook_post_missing_sync_scope_is_rejected(
    app,
    client,
    headers,
    admin_roles,
):
    """Profiles sync account token without `webhooks:user-data` → HTTP 403."""
    user, _identity = get_durable_service_user("svc-commons-profiles")
    access_token = Token.create_personal(
        "missing-user-data-scope",
        user.id,
        scopes=[_WRONG_SCOPE],
    ).access_token

    with app.app_context():
        url = url_for(_WEBHOOK_ENDPOINT)
    with (
        patch(_DO_USER_UPDATE) as do_update,
        patch("invenio_accounts.utils.current_user"),
    ):
        resp = client.post(
            url,
            json={
                "idp": "knowledgeCommons",
                "updates": {
                    "users": [{"id": "anyone", "event": "updated"}],
                },
            },
            headers={
                **headers,
                "Authorization": f"Bearer {access_token}",
            },
        )

    assert resp.status_code == 403
    do_update.delay.assert_not_called()


def test_webhook_post_admin_missing_sync_scope_is_rejected(
    app,
    client,
    headers,
    admin,
    admin_role_need,
):
    """Admin personal token without `webhooks:user-data` → HTTP 403."""
    access_token = Token.create_personal(
        "admin-missing-user-data-scope",
        admin.user.id,
        scopes=[_WRONG_SCOPE],
    ).access_token

    with app.app_context():
        url = url_for(_WEBHOOK_ENDPOINT)
    with (
        patch(_DO_USER_UPDATE) as do_update,
        patch("invenio_accounts.utils.current_user"),
    ):
        resp = client.post(
            url,
            json={
                "idp": "knowledgeCommons",
                "updates": {
                    "users": [{"id": "anyone", "event": "updated"}],
                },
            },
            headers={
                **headers,
                "Authorization": f"Bearer {access_token}",
            },
        )

    assert resp.status_code == 403
    do_update.delay.assert_not_called()


def test_webhook_post_with_sync_scope_is_accepted(
    app,
    client,
    headers,
    admin_roles,
):
    """Personal token that includes `webhooks:user-data` → HTTP 202; job queued."""
    user, _identity = get_durable_service_user("svc-commons-profiles")
    access_token = Token.create_personal(
        "with-user-data-scope",
        user.id,
        scopes=[_SYNC_SCOPE],
    ).access_token
    kc_username = "scope-accepted-user"

    with app.app_context():
        url = url_for(_WEBHOOK_ENDPOINT)
    with (
        patch(_DO_USER_CREATED) as do_created,
        patch("invenio_accounts.utils.current_user"),
    ):
        resp = client.post(
            url,
            json={
                "idp": "knowledgeCommons",
                "updates": {
                    "users": [{"id": kc_username, "event": "created"}],
                },
            },
            headers={
                **headers,
                "Authorization": f"Bearer {access_token}",
            },
        )

    assert resp.status_code == 202
    do_created.delay.assert_called_once_with(
        "knowledgeCommons",
        kc_username=kc_username,
    )


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

    with (
        patch(_DO_USER_UPDATE) as do_update,
        patch("invenio_accounts.utils.current_user"),
    ):
        url = url_for(_WEBHOOK_ENDPOINT)
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
