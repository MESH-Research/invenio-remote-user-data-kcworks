# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""User-update service wires fetch → apply.

These tests check that the user-update service successfully obtains a profile
and invokes the apply step. Field-by-field local outcomes live under
`apply_user_data_changes/`.

Covers:

- Successful path: Profiles is contacted and the apply step is invoked.
- Extra options are passed through to the local-user update step when apply
  runs after a usable profile is in hand.

Related coverage elsewhere:

- Permission gating →
  `user_sync_service/user_update_service_permissions/test_sync_permissions.py`.
- Obtaining a usable Profiles record (or stopping) →
  `user_sync_service/fetch_remote_user_profile/`.
- Field transforms and role reconcile →
  `user_sync_service/apply_user_data_changes/`.
"""

from pprint import pprint
from unittest.mock import patch

import pytest
from flask import current_app
from invenio_access.permissions import system_identity
from invenio_accounts.models import UserIdentity
from invenio_accounts.proxies import current_accounts
from invenio_users_resources.proxies import current_users_service

from invenio_remote_user_data_kcworks.proxies import (
    current_remote_user_data_service as user_data_service,
)
from tests.fixtures.idms import minimal_api_response, minimal_profile


def _subs_url(base_api_url: str, remote_id: str) -> str:
    """Match `UserDataAPIClient.fetch_user_profile(sub_id=...)`.

    Returns:
        Full subs query URL for `requests_mock`.
    """
    return f"{base_api_url}subs/?sub={remote_id}"


@pytest.mark.parametrize(
    "user_email,remote_id,profile_overrides,new_data,user_changes,"
    "new_groups,group_changes",
    [
        (
            "myaddress@hcommons.org",
            "myuser",
            {
                "username": "myuser",
                "email": "myaddress@hcommons.org",
                "name": "My User",
                "first_name": "My",
                "last_name": "User",
                "institutional_affiliation": "Michigan State University",
                "orcid": "0000-0002-1825-0097",
                "groups": [
                    {
                        "id": 1000551,
                        "group_name": "Digital Humanists",
                        "role": "member",
                    },
                    {
                        "id": 1000576,
                        "group_name": "test bpges",
                        "role": "administrator",
                    },
                ],
            },
            {
                "username": "myuser",
                "email": "myaddress@hcommons.org",
                "user_profile": {
                    "full_name": "My User",
                    "name_parts": '{"first": "My", "last": "User"}',
                    "affiliations": "Michigan State University",
                    "identifier_orcid": "0000-0002-1825-0097",
                    "identifier_kc_username": "myuser",
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
                    "full_name": "My User",
                    "name_parts": '{"first": "My", "last": "User"}',
                    "identifier_orcid": "0000-0002-1825-0097",
                    "affiliations": "Michigan State University",
                },
            },
            [
                "knowledgeCommons---1000551|member",
                "knowledgeCommons---1000576|administrator",
            ],
            {
                "added_groups": [
                    "knowledgeCommons---1000551|member",
                    "knowledgeCommons---1000576|administrator",
                ],
                "dropped_groups": [],
                "unchanged_groups": [],
            },
        ),
    ],
)
def test_update_user_from_remote_mock(
    app,
    user_email,
    remote_id,
    profile_overrides,
    new_data,
    user_changes,
    new_groups,
    group_changes,
    user_factory,
    db,
    requests_mock,
    search_clear,
):
    """Successful path: Profiles is contacted and the apply step is invoked."""
    with app.app_context():
        base = current_app.config["IDMS_BASE_API_URL"]

    subs_json = minimal_api_response(remote_id, **profile_overrides).model_dump(
        mode="json",
    )
    requests_mock.get(_subs_url(base, remote_id), json=subs_json)

    fixture_user = user_factory(email=user_email)
    u = fixture_user.user
    if not u.active:
        assert current_accounts.datastore.activate_user(u)
    UserIdentity.create(u, "knowledgeCommons", remote_id)

    actual = user_data_service.update_user_from_remote(
        system_identity,
        u.id,
        "knowledgeCommons",
        remote_id,
    )
    assert {
        "username": actual[0].username,
        "email": actual[0].email,
        "preferences": actual[0].preferences,
        "user_profile": actual[0].user_profile,
    } == new_data
    assert actual[1] == user_changes
    assert sorted(actual[2]) == sorted(new_groups)
    assert actual[3] == group_changes
    myuser_confirm = current_users_service.read(system_identity, u.id).data
    pprint(myuser_confirm)
    assert {
        "username": myuser_confirm["username"],
        "email": myuser_confirm["email"],
        "preferences": {
            k: v
            for k, v in myuser_confirm["preferences"].items()
            if k != "notifications"
        },
        "user_profile": myuser_confirm["profile"],
    } == new_data


def test_update_user_from_remote_delegates_kwargs_to_update_local(
    app,
    user_factory,
    db,
):
    """Extra options are passed through to the local-user update step."""
    myuser = user_factory(email="kw@example.org")
    remote_in = minimal_api_response("sk", profile=minimal_profile())
    group_delta = {
        "added_groups": ["knowledgeCommons---1|member"],
        "dropped_groups": [],
        "unchanged_groups": [],
    }
    with patch(
        "invenio_remote_user_data_kcworks.services.service.CILogonHelpers."
        "calculate_group_changes",
        return_value=group_delta,
    ):
        with patch(
            "invenio_remote_user_data_kcworks.services.service.CILogonHelpers."
            "calculate_user_changes",
            return_value=({}, {}),
        ):
            with patch(
                "invenio_remote_user_data_kcworks.services.service.CILogonHelpers."
                "update_local_user_data",
                return_value={"user": {}, "groups": ["knowledgeCommons---1|member"]},
            ) as update_mock:
                user_data_service.update_user_from_remote(
                    system_identity,
                    myuser.id,
                    "knowledgeCommons",
                    "sk",
                    remote_data=remote_in,
                    dry_run=True,
                )
    assert update_mock.call_args[1]["dry_run"] is True
