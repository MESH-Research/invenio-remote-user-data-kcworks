# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""Request identity after login.

After login (and a session request), the request identity should reflect
remote group memberships from Profiles sync, while still carrying local roles
that are not remote groups (for example `admin`). A local account with no
remote Profiles data should not pick up remote group principals or a KC
username just from logging in.

Covers:

- After login + session request, `g.identity` includes the remote group role
  needs from the synced Profiles groups and still includes a pre-existing
  non-remote role (`admin`).
- A user created without a remote Profiles mock gets only the usual local
  principals (`any_user`, their user id, `authenticated_user`) and no KC
  username.

Related coverage elsewhere:

- Whether login enqueues a sync, and the session throttle that prevents
  double updates → `test_trigger_throttled_sync.py` in this folder.
- Applying remote email / username / profile / prefs / group roles onto the
  local user after login sync →
  `test_e2e_apply_from_login.py`.
- Identity after local logout + session clear →
  `api/logout_receiver/test_identity_after_logout.py`.
- Central / SSO logout webhook → `api/logout_receiver/test_inbound_webhook.py`.
- Local UI logout posting to Profiles → `ui/logout/`.
"""

from flask import g
from flask_login import login_user
from invenio_accounts.testutils import login_user_via_session

from invenio_remote_user_data_kcworks.proxies import (
    current_remote_user_data_service as user_data_service,
)
from invenio_remote_user_data_kcworks.services.group_roles import GroupRolesService
from tests.fixtures.users import user_data_set


def test_identity_after_login_includes_remote_groups_and_admin(
    running_app,
    db,
    client,
    user_factory,
    search_clear,
    celery_worker,
    mock_send_remote_api_update_fixture,
):
    """Login sync leaves remote group principals and a kept admin role."""
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
    grouper.create_new_group(group_name="knowledgeCommons---222222|administrator")
    grouper.create_new_group(group_name="admin")
    grouper.add_user_to_group(
        group_name="knowledgeCommons---222222|administrator", user=myuser1
    )
    grouper.add_user_to_group(group_name="admin", user=myuser1)

    db.session.refresh(myuser1)

    assert len(myuser1.roles)
    assert login_user(myuser1)
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


def test_login_without_remote_mock_has_no_remote_groups_or_kc_username(
    running_app,
    db,
    client,
    user_factory,
    search_clear,
    celery_worker,
    mock_send_remote_api_update_fixture,
):
    """User with no remote Profiles mock gets no remote groups / KC username."""
    # Default factory sets kc_username="myuser" + cilogon oauth and installs
    # Profiles mocks; opt out so this case stays "no remote / no KC username".
    myuser2 = user_factory(
        email="anotheruser@msu.edu",
        kc_username=None,
        oauth_src=None,
        oauth_id=None,
    ).user
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
