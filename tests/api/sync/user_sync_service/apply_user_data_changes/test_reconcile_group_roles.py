# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""Reconcile remote Profiles groups with local Invenio roles.

These tests check how remote group memberships become local roles. Computing
the add/drop set does not call Profiles; applying that set updates the user’s
roles in the database.

Covers:

- Remote group id + role become KC role strings
  (`knowledgeCommons---<id>|<role>`); a Profiles superadmin also gets the
  local `administration` and `administration-moderation` roles; non-remote
  local roles (e.g. `admin`) stay unchanged.
- When local KC roles already match remote, nothing is added or dropped.
- Given a concrete remote vs local group set, the added, dropped, and
  unchanged lists match the fixture (including dropping a stale remote group).
- Applying an added/dropped memberships set updates the user’s roles (drop
  stale, add new, keep unrelated local roles like `admin`).

Related coverage elsewhere:

- Transforming remote profile fields into local username / email / profile /
  preferences → `test_profile_field_transforms.py`.
- Local role helpers (`GroupRolesService`) →
  `api/helper_services/group_roles/`.
- Fetch / unusable Profiles responses →
  `../fetch_remote_user_profile/`.
- Service fetch→apply wiring →
  `../test_user_update_service_integration.py`.
- Login-triggered apply end-to-end (including roles) →
  `on_user_login/test_e2e_apply_from_login.py`.
- Applying a remote *group* onto roles/communities →
  `group_sync_service/apply_group_data_changes/`.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from invenio_utilities_tuw.utils import get_identity_for_user

from invenio_remote_user_data_kcworks.proxies import (
    current_remote_user_data_service as user_data_service,
)
from invenio_remote_user_data_kcworks.services.group_roles import GroupRolesService
from invenio_remote_user_data_kcworks.types.profiles_api import Group, Profile
from invenio_remote_user_data_kcworks.utils.auth import CILogonHelpers
from tests.fixtures.idms import minimal_profile


def _mock_user(
    *,
    username: str = "local_u",
    email: str = "local@example.org",
    roles: list | None = None,
) -> MagicMock:
    """Return a `MagicMock` with the attributes `calculate_group_changes` reads."""
    user = MagicMock()
    user.id = 42
    user.username = username
    user.email = email
    user.active = True
    user.user_profile = {}
    user.preferences = {
        "visibility": "restricted",
        "email_visibility": "restricted",
        "locale": "en",
    }
    user.roles = roles if roles is not None else []
    return user


def test_calculate_group_changes_builds_role_strings_and_superadmin_roles(base_app):
    """Map group id/role to KC role strings; superadmin adds two admin roles."""
    with base_app.app_context():
        profile = minimal_profile(
            username="g",
            name="G",
            email="g@example.org",
            groups=[
                Group(id=1000551, group_name="DH", role="member"),
                Group(id=1000576, group_name="T", role="administrator"),
            ],
            is_superadmin=True,
        )
        user = _mock_user(
            roles=[
                SimpleNamespace(name="admin"),
            ]
        )

        gc = CILogonHelpers.calculate_group_changes(profile, user)

        assert set(gc["added_groups"]) >= {
            "knowledgeCommons---1000551|member",
            "knowledgeCommons---1000576|administrator",
            "administration",
            "administration-moderation",
        }
        assert "admin" in gc["unchanged_groups"]
        assert gc["dropped_groups"] == []


def test_calculate_group_changes_no_delta_when_remote_matches_local_kc_roles(base_app):
    """When local KC roles match remote, added/dropped are empty."""
    with base_app.app_context():
        profile = minimal_profile(
            username="g",
            groups=[
                Group(id=1, group_name="A", role="member"),
            ],
        )
        user = _mock_user(
            roles=[
                SimpleNamespace(name="knowledgeCommons---1|member"),
            ]
        )

        gc = CILogonHelpers.calculate_group_changes(profile, user)

        assert gc["added_groups"] == []
        assert gc["dropped_groups"] == []
        assert gc["unchanged_groups"] == ["knowledgeCommons---1|member"]


@pytest.mark.parametrize(
    "remote_data,starting_data,group_changes",
    [
        (
            {
                "users": {
                    "username": "myuser",
                    "email": "myaddress@hcommons.org",
                    "name": "My User",
                    "first_name": "My",
                    "last_name": "User",
                    "institutional_affiliation": "Michigan State University",
                    "orcid": "0000-0002-1825-0097",
                    "groups": [
                        {
                            "id": 1000576,
                            "name": "awesome-mock",
                            "role": "administrator",
                        },
                        {
                            "id": 1000577,
                            "name": "cool-group2",
                            "role": "member",
                        },
                    ],
                },
            },
            {
                "user": {"email": "myaddress@hcommons.org"},
                "groups": [
                    {"id": 1000570, "name": "cool-group", "role": "administrator"},
                    {"id": 1000577, "name": "cool-group2", "role": "member"},
                ],
            },
            {
                "dropped_groups": ["knowledgeCommons---1000570|administrator"],
                "added_groups": ["knowledgeCommons---1000576|administrator"],
                "unchanged_groups": [
                    "admin",
                    "knowledgeCommons---1000577|member",
                ],
            },
        )
    ],
)
def test_calculate_group_changes_fixture_driven(
    app,
    remote_data,
    starting_data,
    group_changes,
    user_factory,
    db,
):
    """Fixture-driven remote vs local groups yields expected add/drop/unchanged."""
    grouper = GroupRolesService(user_data_service)
    myuser = user_factory(**starting_data["user"]).user
    grouper.create_new_group(group_name="admin")
    grouper.add_user_to_group(group_name="admin", user=myuser)
    for group in starting_data["groups"]:
        grouper.create_new_group(
            group_name=f"knowledgeCommons---{group['id']}|{group['role']}"
        )
        grouper.add_user_to_group(
            group_name=f"knowledgeCommons---{group['id']}|{group['role']}",
            user=myuser,
        )

    actual_group_changes = CILogonHelpers.calculate_group_changes(
        Profile(**{
            **remote_data["users"],
            "academic_interests": [],
            "avatar": None,
            "url": None,
            "is_superadmin": False,
            "groups": [
                {
                    "id": group["id"],
                    "group_name": group["name"],
                    "role": group["role"],
                }
                for group in remote_data["users"]["groups"]
            ],
        }),
        myuser,
    )
    # Membership sets matter; list order follows user.roles / ORM and is unstable.
    for key in ("added_groups", "dropped_groups", "unchanged_groups"):
        assert set(actual_group_changes[key]) == set(group_changes[key])


def test_update_group_memberships_helper(app, user_factory, db):
    """Applying added/dropped memberships updates Invenio roles."""
    test_changed_memberships = {
        "dropped_groups": ["cool-group"],
        "added_groups": ["awesome-mock"],
    }
    expected_updated_memberships = ["admin", "awesome-mock"]
    myuser = user_factory().user

    grouper = GroupRolesService(user_data_service)
    grouper.create_new_group(group_name="cool-group")
    grouper.create_new_group(group_name="admin")
    grouper.add_user_to_group("cool-group", myuser)
    grouper.add_user_to_group("admin", myuser)

    actual_updated_memberships = CILogonHelpers._update_invenio_group_memberships(
        myuser, test_changed_memberships
    )

    assert actual_updated_memberships == expected_updated_memberships
    assert [r.name for r in myuser.roles] == ["admin", "awesome-mock"]
    my_identity = get_identity_for_user(myuser.email)
    assert all(
        n.value
        for n in my_identity.provides
        if n in ["admin", "awesome-mock", "any_user", 5]
    )
