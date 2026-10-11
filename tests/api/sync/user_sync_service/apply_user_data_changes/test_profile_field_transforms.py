# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""Transform remote Profiles fields into local user profile shape.

These tests do not call Profiles over the network. They check that a remote
profile is turned into the local username, email, profile, and preference
fields we would write.

Covers:

- Remote profile overwrites local username, email, KC username id, full name,
  name parts, affiliation, ORCID, and forces visibility / email_visibility to
  `"public"`.
- A plain profile object and the same profile wrapped in an API response
  produce the same transformed local fields.
- A non-empty remote ORCID overwrites the local ORCID on the profile.
- When Profiles sends a blank affiliation, the local affiliation is kept
  (other local profile keys are kept too).
- Given a concrete stale local user and a remote profile, the computed
  “what changed” set and the full new local field blob match the fixture.

Related coverage elsewhere:

- How remote group memberships become local roles →
  `test_reconcile_group_roles.py`.
- Fetch / unusable Profiles responses →
  `../fetch_remote_user_profile/`.
- Service fetch→apply wiring →
  `../test_user_update_service_integration.py`.
- Login-triggered apply end-to-end →
  `on_user_login/test_e2e_apply_from_login.py`.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from invenio_remote_user_data_kcworks.proxies import (
    current_remote_user_data_service as user_data_service,
)
from invenio_remote_user_data_kcworks.services.group_roles import GroupRolesService
from invenio_remote_user_data_kcworks.types.profiles_api import (
    APIResponse,
    Meta,
    Profile,
    SubData,
)
from invenio_remote_user_data_kcworks.utils.auth import CILogonHelpers
from tests.fixtures.idms import minimal_api_response, minimal_profile


def _mock_user(
    *,
    username: str = "local_u",
    email: str = "local@example.org",
    user_profile: dict | None = None,
    preferences: dict | None = None,
    roles: list | None = None,
) -> MagicMock:
    """Return a `MagicMock` with the attributes `calculate_user_changes` reads."""
    user = MagicMock()
    user.id = 42
    user.username = username
    user.email = email
    user.active = True
    user.user_profile = dict(user_profile or {})
    user.preferences = dict(
        preferences
        or {
            "visibility": "restricted",
            "email_visibility": "restricted",
            "locale": "en",
        }
    )
    user.roles = roles if roles is not None else []
    return user


def test_calculate_user_changes_maps_core_fields_from_api_response(base_app):
    """Remote profile overwrites username, email, profile slices, and visibility."""
    with base_app.app_context():
        api = minimal_api_response(
            "sub-1",
            username="remote_u",
            name="Remote Name",
            email="remote@example.org",
            first_name="Remote",
            last_name="Name",
            institutional_affiliation="Some University",
            orcid="0000-0001-0002-0003",
            groups=[],
        )
        user = _mock_user(username="old_u", email="old@example.org")
        changes, new_data = CILogonHelpers.calculate_user_changes(api, user)

        assert new_data["username"] == "remote_u"
        assert new_data["email"] == "remote@example.org"
        assert new_data["user_profile"]["identifier_kc_username"] == "remote_u"
        assert new_data["user_profile"]["full_name"] == "Remote Name"
        assert json.loads(new_data["user_profile"]["name_parts"]) == {
            "first": "Remote",
            "last": "Name",
        }
        assert new_data["user_profile"]["affiliations"] == "Some University"
        assert new_data["user_profile"]["identifier_orcid"] == "0000-0001-0002-0003"
        assert new_data["preferences"]["visibility"] == "public"
        assert new_data["preferences"]["email_visibility"] == "public"

        assert changes["username"] == "remote_u"
        assert changes["email"] == "remote@example.org"
        assert "user_profile" in changes
        assert changes["preferences"]["visibility"] == "public"
        assert changes["preferences"]["email_visibility"] == "public"


def test_calculate_user_changes_accepts_plain_profile_same_as_wrapped(base_app):
    """`Profile` and single-row `APIResponse` yield identical `new_data`."""
    with base_app.app_context():
        prof = minimal_profile(
            username="plain",
            name="Plain User",
            email="plain@example.org",
            first_name="Pl",
            last_name="ain",
            institutional_affiliation=None,
            orcid=None,
            groups=[],
        )
        api = APIResponse(
            data=[SubData(sub="s", profile=prof)],
            meta=Meta(authorized=True),
            next=None,
            previous=None,
        )
        user = _mock_user()
        _, from_profile = CILogonHelpers.calculate_user_changes(prof, user)
        user2 = _mock_user()
        _, from_api = CILogonHelpers.calculate_user_changes(api, user2)

        assert from_profile["username"] == from_api["username"] == "plain"
        assert from_profile["email"] == from_api["email"]
        assert (
            from_profile["user_profile"]["identifier_kc_username"]
            == from_api["user_profile"]["identifier_kc_username"]
        )


def test_calculate_user_changes_overwrites_orcid_from_remote(base_app):
    """When Profiles sends a non-empty ORCID, it becomes `identifier_orcid`."""
    with base_app.app_context():
        api = minimal_api_response(
            "sub-x",
            username="u",
            name="N",
            email="n@example.org",
            first_name="N",
            last_name="U",
            orcid="0000-0001-0002-0003",
            groups=[],
        )
        user = _mock_user(user_profile={"identifier_orcid": "0000-0000-0000-0000"})
        _, new_data = CILogonHelpers.calculate_user_changes(api, user)

        assert new_data["user_profile"]["identifier_orcid"] == "0000-0001-0002-0003"


def test_calculate_user_changes_keeps_local_affiliation_when_remote_blank(base_app):
    """Merged profile keeps prior affiliations when remote sends none."""
    with base_app.app_context():
        api = minimal_api_response(
            "sub-x",
            username="u",
            name="N",
            email="n@example.org",
            first_name="N",
            last_name="U",
            institutional_affiliation=None,
            orcid="",
            groups=[],
        )
        user = _mock_user(
            user_profile={"affiliations": "Prior University", "extra": "kept"},
        )
        _, new_data = CILogonHelpers.calculate_user_changes(api, user)

        assert new_data["user_profile"]["affiliations"] == "Prior University"
        assert new_data["user_profile"]["extra"] == "kept"


@pytest.mark.parametrize(
    "remote_data,starting_data,new_data,user_changes",
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
                "active": True,
                "username": "myuser",
                "email": "myaddress@hcommons.org",
                "user_profile": {
                    "affiliations": "Michigan State University",
                    "full_name": "My User",
                    "identifier_orcid": "0000-0002-1825-0097",
                    "identifier_kc_username": "myuser",
                    "name_parts": '{"first": "My", "last": "User"}',
                },
                "preferences": {
                    "email_visibility": "public",
                    "visibility": "public",
                    "locale": "en",
                    "timezone": "America/Detroit",
                },
            },
            {
                "user_profile": {
                    "affiliations": "Michigan State University",
                    "full_name": "My User",
                    "identifier_orcid": "0000-0002-1825-0097",
                    "name_parts": '{"first": "My", "last": "User"}',
                },
                "preferences": {
                    "visibility": "public",
                    "email_visibility": "public",
                },
            },
        )
    ],
)
def test_calculate_user_changes_fixture_driven(
    app,
    remote_data,
    starting_data,
    new_data,
    user_changes,
    user_factory,
    db,
):
    """Fixture-driven remote vs local user yields expected changes and new_data."""
    grouper = GroupRolesService(user_data_service)
    myuser = user_factory(**starting_data["user"]).user
    # Suite defaults visibility to public; start restricted so the sparse
    # diff is expected to include the public prefs forced from Profiles.
    myuser.preferences = {
        **(myuser.preferences or {}),
        "visibility": "restricted",
        "email_visibility": "restricted",
    }
    db.session.add(myuser)
    db.session.commit()
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

    actual_user_changes, actual_new = CILogonHelpers.calculate_user_changes(
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
    assert actual_new == new_data
    assert actual_user_changes == user_changes
