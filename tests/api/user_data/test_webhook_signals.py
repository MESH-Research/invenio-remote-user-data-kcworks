# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""Focused tests for user-data webhook queue publish, signal, and ext listener.

Full end-to-end workflow (Celery task + remote API + DB) lives in
`tests/api/integration.py`.
"""

from unittest.mock import ANY, MagicMock, patch

from flask import url_for

from invenio_remote_user_data_kcworks.ext import on_remote_data_updated
from invenio_remote_user_data_kcworks.signals import remote_data_updated


def test_remote_data_updated_listener_registered(app):
    """Extension wires `on_remote_data_updated` to `remote_data_updated`."""
    assert remote_data_updated.has_receivers_for(app)


def test_webhook_post_publishes_update_signal(
    app,
    client,
    user_factory,
    headers,
    idms_static_api_auth,
):
    """Webhook "updated" publishes to `user-data-updates` queue and emits signal."""
    oauth_sub = "oauth-sub-webhook-test"
    u = user_factory(
        email="webhook-signal-test@example.com",
        oauth_src="knowledgeCommons",
        oauth_id=oauth_sub,
        kc_username="kc_webhook_user",
    )
    expected_events = [
        {
            "idp": "knowledgeCommons",
            "entity_type": "users",
            "event": "updated",
            "oauth_id": oauth_sub,
            "user_id": u.user.id,
        },
    ]

    queue_proxy = MagicMock()
    queue_proxy.queues = {"user-data-updates": MagicMock()}

    with (
        patch(
            "invenio_remote_user_data_kcworks.views.current_queues",
            queue_proxy,
        ),
        patch(
            "invenio_remote_user_data_kcworks.views.remote_data_updated.send",
        ) as send_sig,
        patch("invenio_accounts.utils.current_user"),
    ):
        with app.app_context():
            url = url_for(
                "invenio_remote_user_data_kcworks.remote_user_data_kcworks_webhook",
            )
        resp = client.post(
            url,
            json={
                "idp": "knowledgeCommons",
                "updates": {
                    "users": [
                        {"id": oauth_sub, "event": "updated"},
                    ],
                },
            },
            headers={**headers, **idms_static_api_auth},
        )

    assert resp.status_code == 202
    queue_proxy.queues["user-data-updates"].publish.assert_called_once_with(
        expected_events,
    )
    send_sig.assert_called_once_with(ANY, events=expected_events)


def test_webhook_post_publishes_create_signal(
    app,
    client,
    user_factory,
    headers,
    idms_static_api_auth,
):
    """Webhook "created" publishes to `user-data-updates` queue and emits signal."""
    oauth_sub = "oauth-sub-webhook-test"
    u = user_factory(
        email="webhook-signal-test@example.com",
        oauth_src="knowledgeCommons",
        oauth_id=oauth_sub,
        kc_username="kc_webhook_user",
    )
    expected_events = [
        {
            "idp": "knowledgeCommons",
            "entity_type": "users",
            "event": "created",
            "oauth_id": oauth_sub,
            "user_id": u.user.id,
        },
    ]

    queue_proxy = MagicMock()
    queue_proxy.queues = {"user-data-updates": MagicMock()}

    with (
        patch(
            "invenio_remote_user_data_kcworks.views.current_queues",
            queue_proxy,
        ),
        patch(
            "invenio_remote_user_data_kcworks.views.remote_data_updated.send",
        ) as send_sig,
        patch("invenio_accounts.utils.current_user"),
    ):
        with app.app_context():
            url = url_for(
                "invenio_remote_user_data_kcworks.remote_user_data_kcworks_webhook",
            )
        resp = client.post(
            url,
            json={
                "idp": "knowledgeCommons",
                "updates": {
                    "users": [
                        {"id": oauth_sub, "event": "created"},
                    ],
                },
            },
            headers={**headers, **idms_static_api_auth},
        )

    assert resp.status_code == 202
    queue_proxy.queues["user-data-updates"].publish.assert_called_once_with(
        expected_events,
    )
    send_sig.assert_called_once_with(ANY, events=expected_events)


def test_on_signal_dispatches_user_update_task(app):
    """Listener drains the queue and calls `do_user_data_update.delay`."""
    event = {
        "entity_type": "users",
        "event": "updated",
        "idp": "knowledgeCommons",
        "oauth_id": "sub-abc",
        "user_id": 4242,
    }
    consume_mock = MagicMock(return_value=[event])

    with app.app_context():
        with patch(
            "invenio_remote_user_data_kcworks.ext.current_queues",
        ) as mock_cq:
            mock_cq.queues = {"user-data-updates": MagicMock()}
            mock_cq.queues["user-data-updates"].consume = consume_mock
            with patch(
                "invenio_remote_user_data_kcworks.ext.do_user_data_update",
            ) as do_update:
                on_remote_data_updated(app, events=[])

    do_update.delay.assert_called_once_with(
        4242,
        "knowledgeCommons",
        "sub-abc",
    )


def test_on_signal_dispatches_user_created_task(app):
    """Listener routes `users` + `created` to `do_user_created.delay`."""
    event = {
        "entity_type": "users",
        "event": "created",
        "idp": "knowledgeCommons",
        "oauth_id": "sub-new",
    }
    consume_mock = MagicMock(return_value=[event])

    with app.app_context():
        with patch(
            "invenio_remote_user_data_kcworks.ext.current_queues",
        ) as mock_cq:
            mock_cq.queues = {"user-data-updates": MagicMock()}
            mock_cq.queues["user-data-updates"].consume = consume_mock
            with patch(
                "invenio_remote_user_data_kcworks.ext.do_user_created",
            ) as do_created:
                on_remote_data_updated(app, events=[])

    do_created.delay.assert_called_once_with("knowledgeCommons", "sub-new")


def test_on_remote_data_updated_dispatches_group_update_task(app):
    """Listener routes `groups` create/update to `do_group_data_update.delay`."""
    event = {
        "entity_type": "groups",
        "event": "updated",
        "idp": "knowledgeCommons",
        "id": "1004290",
    }
    consume_mock = MagicMock(return_value=[event])

    with app.app_context():
        with patch(
            "invenio_remote_user_data_kcworks.ext.current_queues",
        ) as mock_cq:
            mock_cq.queues = {"user-data-updates": MagicMock()}
            mock_cq.queues["user-data-updates"].consume = consume_mock
            with patch(
                "invenio_remote_user_data_kcworks.ext.do_group_data_update",
            ) as do_group:
                on_remote_data_updated(app, events=[])

    do_group.delay.assert_called_once_with("knowledgeCommons", "1004290")
