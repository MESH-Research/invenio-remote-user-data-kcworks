# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""Tests for `RemoteUserDataService.update_user_from_remote`.

`UserDataAPIClient.fetch_user_profile` (see `client.py`) calls:

- `{IDMS_BASE_API_URL}subs/?sub=<remote_id>` for the subject lookup;
- `{IDMS_BASE_API_URL}members/<kc_username>/` when the subs response has no rows
  (`use_sub_endpoint=False`).

Subs responses must JSON-decode to `APIResponse`; members responses must decode to
`Profile` (see `types/profiles_api.py`). Mocks below follow those contracts.
"""

from pprint import pprint
from unittest.mock import MagicMock, patch

import pytest
from flask import current_app
from invenio_access.permissions import system_identity
from invenio_accounts.models import UserIdentity
from invenio_accounts.proxies import current_accounts
from invenio_records_resources.services.errors import PermissionDeniedError
from invenio_users_resources.proxies import current_users_service

from invenio_remote_user_data_kcworks.errors import LocalUserNotFoundError
from invenio_remote_user_data_kcworks.proxies import (
    current_remote_user_data_service as user_data_service,
)
from tests.fixtures.idms import (
    empty_api_response,
    minimal_api_response,
    minimal_profile,
)


def _subs_url(base_api_url: str, remote_id: str) -> str:
    """Match `UserDataAPIClient.fetch_user_profile(sub_id=...)`.

    Returns:
        Full subs query URL for `requests_mock`.
    """
    return f"{base_api_url}subs/?sub={remote_id}"


def _members_url(base_api_url: str, kc_username: str) -> str:
    """Match members fetch (`kc_username` + `use_sub_endpoint=False`).

    Returns:
        Full members URL for `requests_mock`.
    """
    return f"{base_api_url}members/{kc_username}/"


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
                "preferences": {
                    "visibility": "public",
                    "email_visibility": "public",
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
    """Full path: real client HTTP shape against IDMS URLs; real `CILogonHelpers`."""
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


def test_update_user_from_remote_permission_denied(app):
    """`require_permission` runs before any datastore or remote work."""
    with pytest.raises(PermissionDeniedError):
        with patch.object(
            user_data_service,
            "require_permission",
            side_effect=PermissionDeniedError(),
        ):
            user_data_service.update_user_from_remote(
                system_identity,
                999999,
                "knowledgeCommons",
                "sub-x",
            )


def test_update_user_from_remote_local_user_missing(app):
    """Missing local user raises `LocalUserNotFoundError`."""
    missing_id = 9_999_991
    assert current_accounts.datastore.get_user_by_id(missing_id) is None
    with pytest.raises(LocalUserNotFoundError, match="No local Invenio user"):
        user_data_service.update_user_from_remote(
            system_identity,
            missing_id,
            "knowledgeCommons",
            "sub-x",
        )


def test_update_user_from_remote_prefetched_skips_fetch(app, user_factory, db):
    """Pre-fetched authorized `APIResponse` must not call `fetch_user_profile`."""
    myuser = user_factory(
        email="prefetch@example.org",
        oauth_src=None,
        oauth_id=None,
        kc_username=None,
    )
    UserIdentity.create(myuser.user, "knowledgeCommons", "sub-prefetch")
    remote_in = minimal_api_response(
        "sub-prefetch",
        profile=minimal_profile(username="pref"),
    )
    group_delta = {"added_groups": [], "dropped_groups": [], "unchanged_groups": []}
    updated_payload = {"user": {"username": "x"}, "groups": ["g"]}

    with patch(
        "invenio_remote_user_data_kcworks.services.service.UserDataAPIClient."
        "fetch_user_profile",
    ) as fetch_mock:
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
                    return_value=updated_payload,
                ):
                    out = user_data_service.update_user_from_remote(
                        system_identity,
                        myuser.id,
                        "knowledgeCommons",
                        "sub-prefetch",
                        remote_data=remote_in,
                    )

    fetch_mock.assert_not_called()
    assert out[0] is myuser.user
    assert out[1] == updated_payload["user"]
    assert out[2] == updated_payload["groups"]
    assert out[3] == group_delta


def test_update_user_from_remote_unauthorized_meta_early_exit(app, user_factory, db):
    """Unauthorized `meta` returns early with empty group slots."""
    myuser = user_factory(email="unauth@example.org")
    blocked = minimal_api_response(
        "s",
        authorized=False,
        profile=minimal_profile(),
    )
    out = user_data_service.update_user_from_remote(
        system_identity,
        myuser.id,
        "knowledgeCommons",
        "sub-u",
        remote_data=blocked,
    )
    assert out == (myuser.user, blocked, [], {})


def test_update_user_from_remote_no_profile_after_fetch(
    app,
    user_factory,
    db,
    requests_mock,
):
    """Subs empty → members returns unparseable body → `None` path (no local update)."""
    myuser = user_factory(email="empty@example.org")
    UserIdentity.create(myuser.user, "knowledgeCommons", "sub-empty")
    with app.app_context():
        base = current_app.config["IDMS_BASE_API_URL"]

    requests_mock.get(
        _subs_url(base, "sub-empty"),
        json=empty_api_response().model_dump(mode="json"),
    )
    # Invalid profile payload so `Profile(**…)` fails → client returns `None`.
    requests_mock.get(_members_url(base, "myuser"), json={"not": "a profile"})

    out = user_data_service.update_user_from_remote(
        system_identity,
        myuser.id,
        "knowledgeCommons",
        "sub-empty",
    )
    assert out[0] is myuser.user
    assert out[1] is None
    assert out[2] == []
    assert out[3] == {}


def test_update_user_from_remote_fetch_urls_match_client(
    app,
    user_factory,
    db,
    requests_mock,
):
    """Regression: HTTP mocks use the same URLs `UserDataAPIClient` builds."""
    myuser = user_factory(
        email="urls@example.org",
        oauth_src="knowledgeCommons",
        oauth_id="sub-url",
        kc_username="kc_u",
    )
    profile_body = minimal_profile(
        username="kc_u",
        name="N",
        email="urls@example.org",
        first_name="N",
        last_name="U",
    ).model_dump(mode="json")
    with app.app_context():
        base = current_app.config["IDMS_BASE_API_URL"]

    requests_mock.get(
        _subs_url(base, "sub-url"),
        json=empty_api_response().model_dump(mode="json"),
    )
    requests_mock.get(_members_url(base, "kc_u"), json=profile_body)

    with patch(
        "invenio_remote_user_data_kcworks.services.service.CILogonHelpers."
        "calculate_group_changes",
        return_value={
            "added_groups": [],
            "dropped_groups": [],
            "unchanged_groups": [],
        },
    ):
        with patch(
            "invenio_remote_user_data_kcworks.services.service.CILogonHelpers."
            "calculate_user_changes",
            return_value=({}, {}),
        ):
            with patch(
                "invenio_remote_user_data_kcworks.services.service.CILogonHelpers."
                "update_local_user_data",
                return_value={"user": {}, "groups": []},
            ):
                user_data_service.update_user_from_remote(
                    system_identity,
                    myuser.id,
                    "knowledgeCommons",
                    "sub-url",
                )

    history = [r.url for r in requests_mock.request_history]
    assert history == [
        _subs_url(base, "sub-url"),
        _members_url(base, "kc_u"),
    ]


def test_update_user_from_remote_fallback_fetch_by_username(app, user_factory, db):
    """Sub fetch empty → members fetch supplies a `Profile` (signature regression)."""
    myuser = user_factory(
        email="fallback@example.org",
        oauth_src="knowledgeCommons",
        oauth_id="sub-fb",
        kc_username="kc_fb_user",
    )
    profile = minimal_profile(username="kc_fb_user")
    empty = empty_api_response()
    fetch_mock = MagicMock(side_effect=[empty, profile])
    group_delta = {"added_groups": [], "dropped_groups": [], "unchanged_groups": []}
    updated_payload = {"user": {}, "groups": []}

    with patch(
        "invenio_remote_user_data_kcworks.services.service.UserDataAPIClient."
        "fetch_user_profile",
        fetch_mock,
    ):
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
                    return_value=updated_payload,
                ) as update_mock:
                    user_data_service.update_user_from_remote(
                        system_identity,
                        myuser.id,
                        "knowledgeCommons",
                        "sub-fb",
                    )

    assert fetch_mock.call_count == 2
    assert fetch_mock.call_args_list[0].kwargs.get("sub_id") == "sub-fb"
    second_kw = fetch_mock.call_args_list[1].kwargs
    assert second_kw.get("sub_id") is None
    assert second_kw.get("kc_username") == "kc_fb_user"
    assert second_kw.get("use_sub_endpoint") is False
    update_mock.assert_called_once()
    assert update_mock.call_args[0][4] == "knowledgeCommons"


def test_update_user_from_remote_delegates_kwargs_to_update_local(
    app,
    user_factory,
    db,
):
    """Extra kwargs are passed through to `update_local_user_data`."""
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


def test_update_user_from_remote_remote_service_pass_through_idp(app, user_factory, db):
    """`remote_service` stays equal to `idp` when `idp` is not in `KC_REMOTE_IDPS`."""
    myuser = user_factory(email="rawidp@example.org")
    remote_in = minimal_api_response("x", profile=minimal_profile())
    group_delta = {"added_groups": [], "dropped_groups": [], "unchanged_groups": []}
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
                return_value={"user": {}, "groups": []},
            ) as update_mock:
                user_data_service.update_user_from_remote(
                    system_identity,
                    myuser.id,
                    "standalone-idp",
                    "remote-x",
                    remote_data=remote_in,
                )
    assert update_mock.call_args[0][4] == "standalone-idp"
