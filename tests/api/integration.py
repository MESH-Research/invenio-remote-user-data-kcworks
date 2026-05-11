# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""API-layer integration tests that exercise multiple services and I/O paths."""

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from flask import url_for
from flask_login import login_user
from invenio_accounts.profiles import UserProfileDict
from invenio_accounts.proxies import current_accounts

from ..fixtures.users import user_data_set


@pytest.mark.usefixtures("mock_send_remote_api_update_fixture")
def test_user_data_webhook_full_sync_workflow(
    running_app,
    db,
    user_factory,
    client,
    headers,
    search_clear,
    celery_worker,
    idms_static_api_auth,
):
    """Webhook POST → queue/signal → Celery → mocked Profiles API → DB updates."""
    app = running_app.app

    profile_data = user_data_set["user1"]

    u = user_factory(
        email=profile_data["email"],
        oauth_src="cilogon",
        oauth_id=profile_data["oauth_id"],
        kc_username=profile_data["kc_username"],
        new_remote_data=profile_data,
    )
    user_id = u.user.id
    for mock_adapter in u.mock_adapter_subs, u.mock_adapter_members:
        assert mock_adapter is not None
        assert not mock_adapter.called
        assert mock_adapter.call_count == 0

    with app.app_context():
        ping_url = url_for(
            "invenio_remote_user_data_kcworks.remote_user_data_kcworks_webhook_deprecated",
        )
    response = client.get(ping_url)
    assert response.status_code == 200
    assert json.loads(response.data) == {
        "message": "Webhook receiver is active",
        "status": 200,
    }
    assert not u.mock_adapter_subs.called
    assert u.mock_adapter_subs.call_count == 0
    assert not u.mock_adapter_members.called
    assert u.mock_adapter_members.call_count == 0

    with patch("invenio_accounts.utils.current_user"):
        with app.app_context():
            post_url = url_for(
                "invenio_remote_user_data_kcworks.remote_user_data_kcworks_webhook_deprecated",
            )
        response2 = client.post(
            post_url,
            json={
                "idp": "knowledgeCommons",
                "updates": {
                    "users": [
                        {
                            "id": profile_data["oauth_id"],
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
                    "id": profile_data["oauth_id"],
                    "event": "updated",
                },
            ],
        },
    }

    assert u.mock_adapter_subs.called
    assert u.mock_adapter_subs.call_count == 1
    assert not u.mock_adapter_members.called

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


def test_user_data_sync_on_login_workflow(
    running_app,
    db,
    user_factory,
    search_clear,
    celery_worker,
    mock_send_remote_api_update_fixture,
):
    """Test that the user data is synced when a user logs in.

    The actual api call is mocked, so this tests that the api request is made
    and that the user data is updated in Invenio.

    - Includes test of username updating if the remote username
      has changed.

    Also tests that the api call does *not* happen for simple programmatic
    user creation. It only happens when the user logs in.
    """
    app = running_app.app
    # Mock additional user data from the remote service
    # api response
    new_data_payload = user_data_set["user1"]

    # Create a user with a stale local KC handle; the mocked subs payload still
    # carries `user_data_set["user1"]["kc_username"]` as `profile.username`
    # (see `user_data_to_remote_data`).
    u = user_factory(
        email="originalemail@kcommons.org",
        oauth_src="cilogon",
        oauth_id=new_data_payload["oauth_id"],
        kc_username="beforesync",
        new_remote_data=new_data_payload,
    )
    user_id = u.user.id
    old_username = u.user.username
    assert old_username == "beforesync"

    # `on_user_logged_in` only enqueues `do_user_data_update` when `user.updated`
    # is older than `INVENIO_REMOTE_USER_DATA_UPDATE_INTERVAL` (default 30s).
    with app.app_context():
        u.user.updated = datetime.now(UTC) - timedelta(seconds=120)
        db.session.commit()

    for mock_adapter in u.mock_adapter_subs, u.mock_adapter_members:
        assert not mock_adapter.called
        assert mock_adapter.call_count == 0
    login_user(u.user)
    assert u.mock_adapter_subs.called
    assert u.mock_adapter_subs.call_count == 1
    assert not u.mock_adapter_members.called
    assert u.mock_adapter_members.call_count == 0

    # Celery task updates the user in another db session;
    # expire the test session's cached user so get_user_by_email
    # loads fresh data from the DB.
    db.session.expire(u.user)

    refreshed_user = current_accounts.datastore.get_user_by_id(user_id)

    # Ensure that remote email changes are propagated.
    assert refreshed_user.email == new_data_payload["email"]
    assert refreshed_user.email != "originalemail@kcommons.org"
    # Ensure that remote username changes are propagated.
    assert refreshed_user.username == new_data_payload["kc_username"]
    assert refreshed_user.username != old_username
    # Ensure that remote profile data is propagated.
    profile: UserProfileDict = refreshed_user.user_profile
    assert profile.get("full_name") == new_data_payload["name"]
    assert profile.get("affiliations") == new_data_payload["institutional_affiliation"]
    assert profile.get("identifier_orcid") == new_data_payload["orcid"]
    assert profile.get("identifier_kc_username") == new_data_payload["kc_username"]
    assert json.loads(profile.get("name_parts")) == {
        "first": new_data_payload["first_name"],
        "last": new_data_payload["last_name"],
    }
    assert refreshed_user.preferences.get("visibility") == "public"
    assert refreshed_user.preferences.get("email_visibility") == "public"

    # Check that the user is a member of the linked communities
    assert sorted([r.name for r in refreshed_user.roles]) == sorted([
        "knowledgeCommons---12345|administrator",
        "knowledgeCommons---67891|member",
    ])
