# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""API-layer integration tests that exercise multiple services and I/O paths."""

import json
import time
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from flask import g, url_for
from flask_login import login_user, logout_user
from invenio_access.permissions import system_identity
from invenio_accounts.profiles import UserProfileDict
from invenio_accounts.proxies import current_accounts
from invenio_accounts.testutils import login_user_via_session
from invenio_users_resources.proxies import current_users_service

from invenio_remote_user_data_kcworks.proxies import (
    current_remote_user_data_service as user_data_service,
)
from invenio_remote_user_data_kcworks.services.group_roles import GroupRolesService

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

    # ensure we have a clear start
    assert u.user.user_profile == {"identifier_kc_username": "user1"}
    for mock_adapter in u.mock_adapter_subs, u.mock_adapter_members:
        assert mock_adapter is not None
        assert not mock_adapter.called
        assert mock_adapter.call_count == 0

    # ensure webhook is receiving
    with app.app_context():
        ping_url = url_for(
            "invenio_remote_user_data_kcworks.remote_user_data_kcworks_webhook",
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
                "invenio_remote_user_data_kcworks.remote_user_data_kcworks_webhook",
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


def test_group_roles_sync_on_login_logout(
    running_app,
    db,
    client,
    user_factory,
    search_clear,
    celery_worker,
    mock_send_remote_api_update_fixture,
):
    """Test login including group role updates.

    Complements `test_user_data_sync_on_login_workflow` by asserting remote
    group principals on the request identity and a second user without remote
    mock subscriptions.
    """
    app = running_app.app

    new_data_payload = user_data_set["user1"]
    expected_remote_groups = [
        f"knowledgeCommons---{group['id']}|{group['role']}"
        for group in new_data_payload["groups"]
    ]

    u1_fixture = user_factory(
        email="originalemail@kcommons.org",
        oauth_src="cilogon",
        oauth_id=new_data_payload["oauth_id"],
        kc_username="beforesync",
        new_remote_data=new_data_payload,
    )
    myuser1 = u1_fixture.user

    grouper = GroupRolesService(user_data_service)
    grouper.create_new_group(group_name="knowledgeCommons---222222|admin")
    grouper.create_new_group(group_name="admin")
    grouper.add_user_to_group(
        group_name="knowledgeCommons---222222|admin", user=myuser1
    )
    grouper.add_user_to_group(group_name="admin", user=myuser1)

    db.session.refresh(myuser1)

    # Role commits refresh `user.updated`; backdate before login for interval gate.
    with app.app_context():
        u1_fixture.user.updated = datetime.now(UTC) - timedelta(seconds=120)
        db.session.commit()
        app.logger.debug(f"In test set updated to {myuser1.updated}")
    u = current_accounts.datastore.get_user_by_id(myuser1.id)
    app.logger.debug(f"in test set updated to {u.updated}")

    for mock_adapter in u1_fixture.mock_adapter_subs, u1_fixture.mock_adapter_members:
        assert not mock_adapter.called
        assert mock_adapter.call_count == 0

    assert len(myuser1.roles)
    assert login_user(myuser1)
    assert u1_fixture.mock_adapter_subs is not None
    assert u1_fixture.mock_adapter_subs.called
    db.session.expire(myuser1)
    login_user_via_session(client, user=myuser1)
    client.get("/api")
    my_identity = g.identity
    assert (
        len([
            n.value
            for n in my_identity.provides
            if n.value
            in [
                *expected_remote_groups,
                "any_user",
                myuser1.id,
                "authenticated_user",
                "admin",
            ]
        ])
        == 6
    )
    assert (
        len([
            n.value
            for n in my_identity.provides
            if n.value
            not in [
                *expected_remote_groups,
                "any_user",
                myuser1.id,
                "authenticated_user",
                "admin",
            ]
        ])
        == 0
    )

    myuser1 = current_users_service.read(system_identity, myuser1.id).data
    assert myuser1["username"] == new_data_payload["kc_username"]
    assert myuser1["email"] == new_data_payload["email"]
    assert myuser1["profile"]["full_name"] == new_data_payload["name"]
    assert (
        myuser1["profile"]["affiliations"]
        == new_data_payload["institutional_affiliation"]
    )
    assert myuser1["profile"]["identifier_orcid"] == new_data_payload["orcid"]
    assert json.loads(myuser1["profile"]["name_parts"]) == {
        "first": new_data_payload["first_name"],
        "last": new_data_payload["last_name"],
    }
    assert myuser1["preferences"]["email_visibility"] == "public"
    assert myuser1["preferences"]["visibility"] == "public"
    assert myuser1["preferences"]["locale"] == "en"
    assert myuser1["preferences"]["timezone"] == "Europe/Zurich"

    logout_user()
    with client.session_transaction() as session:
        if "user_id" in session:
            del session["user_id"]
            del session["_user_id"]
    time.sleep(10)
    client.get("/api")
    my_identity = g.identity
    assert len([n.value for n in my_identity.provides if n.value in ["any_user"]]) == 1
    assert (
        len([n.value for n in my_identity.provides if n.value not in ["any_user"]]) == 0
    )

    myuser2 = user_factory(email="anotheruser@msu.edu").user
    assert myuser2.roles == []
    login_user(myuser2)
    login_user_via_session(client, email=myuser2.email)
    client.get("/api")
    my_identity = g.identity
    assert (
        len([
            n.value
            for n in my_identity.provides
            if n.value in ["any_user", myuser2.id, "authenticated_user"]
        ])
        == 3
    )
    assert (
        len([
            n.value
            for n in my_identity.provides
            if n.value not in ["any_user", myuser2.id, "authenticated_user"]
        ])
        == 0
    )
    assert myuser2.username is None
