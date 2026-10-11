# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""Login-triggered sync: local account ends up matching Profiles.

Someone logs in with a stale local account; the login sync job runs; the local
user row matches Profiles. Enqueue and throttle ownership stay in
`test_trigger_throttled_sync.py`; this file owns the post-login apply
assertions.

Covers:

- Remote email overwrites local email.
- Remote KC username overwrites local SQL username.
- Profile picks up full name, affiliation, ORCID, KC username, and name parts.
- Preferences visibility and email visibility become `"public"`.
- Preferences locale and timezone are as expected on a users-service read
  (`en`, `America/Detroit` — package `BABEL_DEFAULT_TIMEZONE`).
- Local group roles match the remote groups set (stale remote-shaped roles
  dropped).

Related coverage elsewhere:

- Whether login enqueues a sync, and the session throttle →
  `test_trigger_throttled_sync.py`.
- Request identity after login → `test_identity_after_login.py`.
- Rewriting `kc_username` on published and draft records after a rename →
  `on_username_changed/test_e2e_from_login.py`.
- Transform / group helpers without a full login path →
  `user_sync_service/apply_user_data_changes/`.
- Fetch / unusable Profiles responses →
  `user_sync_service/fetch_remote_user_profile/`.
- Service fetch→apply wiring →
  `user_sync_service/test_user_update_service_integration.py`.
"""

import json

from flask_login import login_user
from invenio_access.permissions import system_identity
from invenio_accounts.profiles import UserProfileDict
from invenio_accounts.proxies import current_accounts
from invenio_users_resources.proxies import current_users_service

from invenio_remote_user_data_kcworks.proxies import (
    current_remote_user_data_service as user_data_service,
)
from invenio_remote_user_data_kcworks.services.group_roles import GroupRolesService
from tests.fixtures.users import user_data_set


def test_login_sync_applies_remote_user_fields(
    running_app,
    db,
    user_factory,
    search_clear,
    celery_worker,
    mock_send_remote_api_update_fixture,
):
    """Login-triggered sync overwrites stale local account fields from Profiles."""
    new_data_payload = user_data_set["user1"]

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

    login_user(u.user)
    db.session.expire(u.user)

    refreshed_user = current_accounts.datastore.get_user_by_id(user_id)

    assert refreshed_user.email == new_data_payload["email"]
    assert refreshed_user.email != "originalemail@kcommons.org"
    assert refreshed_user.username == new_data_payload["kc_username"]
    assert refreshed_user.username != old_username

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

    assert sorted([r.name for r in refreshed_user.roles]) == sorted([
        "knowledgeCommons---12345|administrator",
        "knowledgeCommons---67891|member",
    ])


def test_login_sync_applies_prefs_visible_on_users_service_read(
    running_app,
    db,
    user_factory,
    search_clear,
    celery_worker,
    mock_send_remote_api_update_fixture,
):
    """Login sync: users-service read shows profile + locale/timezone prefs."""
    new_data_payload = user_data_set["user1"]
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

    login_user(myuser1)
    db.session.expire(myuser1)

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
    assert myuser1["preferences"]["timezone"] == "America/Detroit"
