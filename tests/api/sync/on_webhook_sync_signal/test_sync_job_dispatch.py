# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""Queue the correct background job for each Profiles sync ping payload.

Covers:

- User updated → queue the user-update job.
- User created → queue the user-created job.
- Group updated → queue the group-update job.
- Group deleted → do **not** queue a delete job (not implemented yet; only logged).

Account-linked (association) job enqueue is covered under
`tests/api/sync/on_account_linked/`.

End-to-end user apply (job runs → DB updates):
`test_e2e_apply_from_webhook.py` in this folder.
Group apply (service-side): `group_sync_service/apply_group_data_changes/`.
"""

from unittest.mock import patch

from flask import url_for


def test_webhook_post_enqueues_user_update_task(
    app,
    client,
    user_factory,
    headers,
    idms_static_api_auth,
):
    """Webhook "updated" enqueues `do_user_data_update.delay`."""
    oauth_sub = "oauth-sub-webhook-test"
    kc_username = "kc_webhook_user"
    u = user_factory(
        email="webhook-signal-test@example.com",
        oauth_id=oauth_sub,
        kc_username=kc_username,
    )

    with (
        patch(
            "invenio_remote_user_data_kcworks.views.do_user_data_update",
        ) as do_update,
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
                        {"id": kc_username, "event": "updated"},
                    ],
                },
            },
            headers={**headers, **idms_static_api_auth},
        )

    assert resp.status_code == 202
    do_update.delay.assert_called_once_with(
        u.user.id,
        "knowledgeCommons",
        kc_username=kc_username,
    )


def test_webhook_post_enqueues_user_created_task(
    app,
    client,
    user_factory,
    headers,
    idms_static_api_auth,
):
    """Webhook "created" enqueues `do_user_created.delay`."""
    oauth_sub = "oauth-sub-webhook-test"
    kc_username = "kc_webhook_user"
    user_factory(
        email="webhook-signal-test@example.com",
        oauth_id=oauth_sub,
        kc_username=kc_username,
    )

    with (
        patch(
            "invenio_remote_user_data_kcworks.views.do_user_created",
        ) as do_created,
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
                        {"id": kc_username, "event": "created"},
                    ],
                },
            },
            headers={**headers, **idms_static_api_auth},
        )

    assert resp.status_code == 202
    do_created.delay.assert_called_once_with(
        "knowledgeCommons",
        kc_username=kc_username,
    )


def test_webhook_post_enqueues_group_update_task(
    app,
    client,
    headers,
    idms_static_api_auth,
):
    """Webhook group create/update enqueues `do_group_data_update.delay`."""
    with (
        patch(
            "invenio_remote_user_data_kcworks.views.do_group_data_update",
        ) as do_group,
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
                    "groups": [
                        {"id": "1004290", "event": "updated"},
                    ],
                },
            },
            headers={**headers, **idms_static_api_auth},
        )

    assert resp.status_code == 202
    do_group.delay.assert_called_once_with("knowledgeCommons", "1004290")


def test_webhook_post_group_deleted_does_not_enqueue_job(
    app,
    client,
    headers,
    idms_static_api_auth,
    caplog,
):
    """Group deleted is accepted but does not queue a background job yet."""
    with app.app_context():
        url = url_for(
            "invenio_remote_user_data_kcworks.remote_user_data_kcworks_webhook",
        )
    with (
        patch(
            "invenio_remote_user_data_kcworks.views.do_group_data_update",
        ) as do_group,
        patch("invenio_accounts.utils.current_user"),
        caplog.at_level("ERROR"),
    ):
        resp = client.post(
            url,
            json={
                "idp": "knowledgeCommons",
                "updates": {
                    "groups": [
                        {"id": "1004290", "event": "deleted"},
                    ],
                },
            },
            headers={**headers, **idms_static_api_auth},
        )

    assert resp.status_code == 202
    do_group.delay.assert_not_called()
    assert any(
        "not yet implemented" in record.getMessage() for record in caplog.records
    )
