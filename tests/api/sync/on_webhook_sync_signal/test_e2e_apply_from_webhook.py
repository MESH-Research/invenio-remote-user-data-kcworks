# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""Webhook-triggered sync: local account ends up matching Profiles.

One path only: existing local user, `users` / `updated` ping, through to a
changed DB row. Celery runs for real (`.delay` is not mocked). Parallel to
`on_user_login/test_e2e_apply_from_login.py` for the login surface.

Covers:

- Start from a local user already linked to CILogon / KC username (empty
  remote profile data on the fixture).
- Stub Profiles HTTP (members + subs) for that person.
- Authenticated GET on the sync webhook → HTTP 200 “receiver is active”,
  and Profiles is not called yet.
- Authenticated POST with `idp: knowledgeCommons` and
  `users: [{id: <kc_username>, event: updated}]` → HTTP 202 with the same
  `updates` echoed back.
- After the job runs, Profiles was hit via members once (not via subs).
- Reloaded local user has the expected email, full name, KC username,
  ORCID, name parts, affiliation, and group roles.

Does not cover: user create, group pings, association, login sync,
username rename on records, wrong auth, or the subs-first fetch path.

Related coverage elsewhere:

- Job dispatch / which ping kind → `test_sync_job_dispatch.py`.
- Webhook auth / scopes → `test_user_webhook_auth.py`.
- Login-triggered apply e2e → `on_user_login/test_e2e_apply_from_login.py`.
- Field transforms / role reconcile without a webhook →
  `user_sync_service/apply_user_data_changes/`.
"""

import json
from unittest.mock import patch

import pytest
from flask import url_for
from invenio_accounts.proxies import current_accounts

from tests.fixtures.users import user_data_set


@pytest.mark.usefixtures("mock_send_remote_api_update_fixture")
def test_user_data_webhook_full_sync_workflow(
    running_app,
    db,
    user_factory,
    client,
    requests_mock,
    headers,
    search_clear,
    celery_worker,
    idms_static_api_auth,
    user_data_to_remote_data,
):
    """Webhook POST → Celery → members Profiles API → DB updates."""
    app = running_app.app

    profile_data = user_data_set["user1"]

    u = user_factory(
        email=profile_data["email"],
        oauth_src="cilogon",
        oauth_id=profile_data["oauth_id"],
        kc_username=profile_data["kc_username"],
        new_remote_data={},
    )
    user_id = u.user.id

    for mock_adapter in u.mock_adapter_subs, u.mock_adapter_members:
        assert mock_adapter is not None
        assert not mock_adapter.called
        assert mock_adapter.call_count == 0

    base_url = app.config.get("IDMS_BASE_API_URL")
    mock_remote_data_subs, mock_remote_data_members, _ = user_data_to_remote_data(
        kc_username=profile_data["kc_username"],
        email=profile_data["email"],
        user_data=profile_data,
        oauth_id=profile_data["oauth_id"],
    )
    mock_adapter_members = requests_mock.get(
        f"{base_url}members/{profile_data['kc_username']}/",
        json=mock_remote_data_members,
    )
    mock_adapter_subs = requests_mock.get(
        f"{base_url}subs/?sub={profile_data['oauth_id']}",
        json=mock_remote_data_subs,
    )

    # ensure webhook is receiving (authenticated GET)
    with app.app_context():
        ping_url = url_for(
            "invenio_remote_user_data_kcworks.remote_user_data_kcworks_webhook",
        )
    response = client.get(ping_url, headers=idms_static_api_auth)
    assert response.status_code == 200
    assert json.loads(response.data) == {
        "message": "Webhook receiver is active",
        "status": 200,
    }
    assert not mock_adapter_members.called
    assert not mock_adapter_subs.called

    with patch("invenio_accounts.utils.current_user"):
        with app.app_context():
            post_url = url_for(
                "invenio_remote_user_data_kcworks.remote_user_data_kcworks_webhook",
            )
        response2 = client.post(
            post_url,
            json={
                "idp": "knowledgeCommons",
                "updates": {
                    "users": [
                        {
                            "id": profile_data["kc_username"],
                            "event": "updated",
                        },
                    ],
                },
            },
            headers={**headers, **idms_static_api_auth},
        )

    assert response2.status_code == 202
    assert response2.json == {
        "message": "Webhook notification accepted",
        "status": 202,
        "updates": {
            "users": [
                {
                    "id": profile_data["kc_username"],
                    "event": "updated",
                },
            ],
        },
    }

    assert mock_adapter_members.called
    assert mock_adapter_members.call_count == 1
    assert not mock_adapter_subs.called

    # Celery task updates the user in another db session;
    # expire the test session's cached user so get_user_by_email
    # loads fresh data from the DB.
    db.session.expire(u.user)

    user = current_accounts.datastore.get_user_by_id(user_id)
    assert user.email == profile_data["email"]
    assert user.user_profile.get("full_name") == profile_data["name"]
    assert (
        user.user_profile.get("identifier_kc_username") == profile_data["kc_username"]
    )
    assert user.user_profile.get("identifier_orcid") == profile_data["orcid"]
    assert json.loads(user.user_profile.get("name_parts")) == {
        "first": profile_data["first_name"],
        "last": profile_data["last_name"],
    }
    assert sorted(r.name for r in user.roles) == sorted([
        "knowledgeCommons---12345|administrator",
        "knowledgeCommons---67891|member",
    ])
    assert (
        user.user_profile.get("affiliations")
        == profile_data["institutional_affiliation"]
    )
