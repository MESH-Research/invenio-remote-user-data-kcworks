# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Right remote-system settings and reading a Profiles sync ping.

The ping JSON has an `idp` field. That value is either:

- `knowledgeCommons` — the key in `REMOTE_USER_DATA_API_ENDPOINTS`, or
- an alias from `KC_REMOTE_IDPS` (in our config, `cilogon`). Aliases still
  load the `knowledgeCommons` endpoint settings; `cilogon` is kept as the
  OAuth identity method name for local user lookup.

Covers:

- `idp: "knowledgeCommons"` → settings under that
  `REMOTE_USER_DATA_API_ENDPOINTS` key; auth method `cilogon` (first
  `KC_REMOTE_IDPS` entry).
- `idp: "cilogon"` → same endpoint settings as `knowledgeCommons`, auth
  method `cilogon`.
- Unknown `idp` → HTTP 400; no background job queued.
- Body missing `idp` / `updates` → HTTP 400; no background job queued.
- `updates` key not in that system’s allowed entity types → HTTP 400; no job.
- Event name not in that entity’s allowed events → HTTP 400; no job.
"""

from unittest.mock import patch

from flask import url_for

from invenio_remote_user_data_kcworks.views import _resolve_webhook_config_idp

_DO_USER_UPDATE = "invenio_remote_user_data_kcworks.views.do_user_data_update"
_WEBHOOK_ENDPOINT = (
    "invenio_remote_user_data_kcworks.remote_user_data_kcworks_webhook"
)


def test_resolve_webhook_config_idp_knowledge_commons(app):
    """`knowledgeCommons` idp maps to itself with cilogon auth method."""
    with app.app_context():
        config_idp, auth_method = _resolve_webhook_config_idp("knowledgeCommons")
    assert config_idp == "knowledgeCommons"
    assert auth_method == "cilogon"


def test_resolve_webhook_config_idp_cilogon_alias(app):
    """KC_REMOTE_IDPS aliases resolve to knowledgeCommons config."""
    with app.app_context():
        config_idp, auth_method = _resolve_webhook_config_idp("cilogon")
    assert config_idp == "knowledgeCommons"
    assert auth_method == "cilogon"


def test_webhook_post_unknown_idp_is_rejected(
    app, client, headers, idms_static_api_auth
):
    """Unknown `idp` value is rejected before any job is queued."""
    with app.app_context():
        url = url_for(_WEBHOOK_ENDPOINT)
    with (
        patch(_DO_USER_UPDATE) as do_update,
        patch("invenio_accounts.utils.current_user"),
    ):
        resp = client.post(
            url,
            json={
                "idp": "not-a-configured-idp",
                "updates": {
                    "users": [{"id": "anyone", "event": "updated"}],
                },
            },
            headers={**headers, **idms_static_api_auth},
        )

    assert resp.status_code == 400
    do_update.delay.assert_not_called()


def test_webhook_post_missing_required_fields_is_rejected(
    app, client, headers, idms_static_api_auth
):
    """Payload without `idp` / `updates` is rejected as malformed."""
    with app.app_context():
        url = url_for(_WEBHOOK_ENDPOINT)
    with (
        patch(_DO_USER_UPDATE) as do_update,
        patch("invenio_accounts.utils.current_user"),
    ):
        resp = client.post(
            url,
            json={"hello": "world"},
            headers={**headers, **idms_static_api_auth},
        )

    assert resp.status_code == 400
    do_update.delay.assert_not_called()


def test_webhook_post_unknown_entity_type_is_rejected(
    app, client, headers, idms_static_api_auth
):
    """Entity types not listed for the remote system yield no valid events."""
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
                    "widgets": [{"id": "x", "event": "updated"}],
                },
            },
            headers={**headers, **idms_static_api_auth},
        )

    assert resp.status_code == 400
    do_update.delay.assert_not_called()


def test_webhook_post_unknown_event_is_rejected(
    app, client, headers, idms_static_api_auth
):
    """Event names not allowed for that entity type yield no valid events."""
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
                    "users": [{"id": "anyone", "event": "frobnicated"}],
                },
            },
            headers={**headers, **idms_static_api_auth},
        )

    assert resp.status_code == 400
    do_update.delay.assert_not_called()
