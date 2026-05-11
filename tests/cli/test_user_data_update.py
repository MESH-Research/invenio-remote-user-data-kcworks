# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""Tests of user data update cli."""

import copy
import json

import pytest
from invenio_access.permissions import system_identity
from invenio_accounts.models import UserIdentity
from invenio_accounts.proxies import current_accounts
from invenio_users_resources.proxies import current_users_service

from invenio_remote_user_data_kcworks.proxies import current_remote_user_data_service
from invenio_remote_user_data_kcworks.types.profiles_api import APIResponse
from invenio_remote_user_data_kcworks.utils.auth import CILogonHelpers


def _expected_calculated_user_data(api: APIResponse, user):
    """Mirror `calculate_user_changes` without mutating `user` (deep-copy prefs).

    Args:
        api: Parsed Profiles `subs` API response.
        user: Local user before update.

    Returns:
        Sparse user diff and full calculated user data (same shapes as
        `calculate_user_changes`).
    """
    profile = api.data[0].profile
    initial_user_data = {
        "username": user.username,
        "preferences": copy.deepcopy(dict(user.preferences)),
        "roles": list(user.roles),
        "email": user.email,
        "active": user.active,
        "user_profile": copy.deepcopy(dict(user.user_profile or {})),
    }

    new_data: dict = {"active": True}
    new_data["user_profile"] = {**initial_user_data["user_profile"]}
    new_data["user_profile"].update({
        "full_name": profile.name,
        "name_parts": json.dumps({
            "first": profile.first_name,
            "last": profile.last_name,
        }),
    })
    if profile.institutional_affiliation:
        new_data["user_profile"]["affiliations"] = profile.institutional_affiliation
    if profile.orcid and profile.orcid != "":
        new_data["user_profile"]["identifier_orcid"] = profile.orcid
    new_data["user_profile"]["identifier_kc_username"] = profile.username
    new_data["username"] = profile.username
    new_data["email"] = profile.email
    new_data["preferences"] = copy.deepcopy(dict(user.preferences))
    new_data["preferences"].update({
        "visibility": "public",
        "email_visibility": "public",
    })

    user_changes = CILogonHelpers._diff_between_nested_dicts(
        initial_user_data, new_data
    )
    return user_changes, new_data


@pytest.mark.parametrize(
    "user_email,remote_id,api_response",
    [
        (
            "myaddress@hcommons.org",
            "myuser",
            {
                "data": [
                    {
                        "sub": "http://cilogon.org/serverE/users/XXXXXX",
                        "profile": {
                            "username": "myuser",
                            "email": "myaddress@hcommons.org",
                            "name": "My User",
                            "first_name": "My",
                            "last_name": "User",
                            "institutional_affiliation": "Michigan State University",
                            "orcid": "0000-0002-1825-0097",
                            "academic_interests": [],
                            "avatar": (
                                "https://www.gravatar.com/avatar/"
                                "e8e059e46712e40575b50a784af4b1deb6a2ce13e113fc246b1a6af129107719"
                                "?s=150"
                            ),
                            "groups": [
                                {
                                    "id": 1000551,
                                    "group_name": "Digital Humanists",
                                    "role": "member",
                                    "url": (
                                        "http://profile.hcommons.org/api/v1/groups/1000551/"
                                    ),
                                },
                                {
                                    "id": 1000576,
                                    "group_name": "test bpges",
                                    "role": "administrator",
                                    "url": (
                                        "http://profile.hcommons.org/api/v1/groups/1000576/"
                                    ),
                                },
                            ],
                            "is_superadmin": False,
                        },
                        "idp_name": "Gmail",
                    }
                ],
                "meta": {"authorized": True},
                "next": None,
                "previous": None,
            },
        ),
    ],
)
def test_cli_update_one(
    app,
    user_email,
    remote_id,
    api_response,
    user_factory,
    db,
    requests_mock,
):
    """Subs endpoint returns `APIResponse` with `group_name` and wire roles."""
    idms_base = app.config["IDMS_BASE_API_URL"]

    parsed = APIResponse(**api_response)
    requests_mock.get(
        f"{idms_base}subs/?sub={remote_id}",
        json=api_response,
    )

    fixture_user = user_factory(email=user_email, oauth_src=None, oauth_id=None)
    u = fixture_user.user
    if not u.active:
        assert current_accounts.datastore.activate_user(u)
    UserIdentity.create(u, "knowledgeCommons", remote_id)

    expected_user_changes, expected_new_data = _expected_calculated_user_data(parsed, u)
    expected_group_changes = CILogonHelpers.calculate_group_changes(parsed, u)

    actual = current_remote_user_data_service.update_user_from_remote(
        system_identity,
        u.id,
        "knowledgeCommons",
        remote_id,
    )

    assert actual[0] is not None
    assert {
        "username": actual[0].username,
        "email": actual[0].email,
        "preferences": actual[0].preferences,
        "user_profile": actual[0].user_profile,
    } == {
        "username": expected_new_data["username"],
        "email": expected_new_data["email"],
        "preferences": expected_new_data["preferences"],
        "user_profile": expected_new_data["user_profile"],
    }
    assert actual[1] == expected_user_changes
    assert sorted(actual[2]) == sorted([
        "knowledgeCommons---1000551|member",
        "knowledgeCommons---1000576|administrator",
    ])
    assert actual[3] == expected_group_changes

    myuser_confirm = current_users_service.read(system_identity, u.id).data
    assert {
        "username": myuser_confirm["username"],
        "email": myuser_confirm["email"],
        "preferences": {
            k: v
            for k, v in myuser_confirm["preferences"].items()
            if k != "notifications"
        },
        "user_profile": myuser_confirm["profile"],
    } == {
        "username": expected_new_data["username"],
        "email": expected_new_data["email"],
        "preferences": {
            k: v
            for k, v in expected_new_data["preferences"].items()
            if k != "notifications"
        },
        "user_profile": expected_new_data["user_profile"],
    }
