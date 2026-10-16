# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""How the user-update service looks up a Profiles user record.

Covers:

- The HTTP calls use the same Profiles subs / members URLs the client builds.
- An empty lookup by linked account falls back to fetch by KC username.
- When the identity provider name is not a known alias, we keep using that
  name as the remote service key.

Related coverage elsewhere:

- Missing local user → `test_local_user_missing.py`.
- Skip fetch when a usable profile is already in hand →
  `test_prefetched_skips_fetch.py`.
- Unusable remote responses → `test_unusable_profile_stops.py`.
- Outbound HTTP client details → `api/clients/`.
"""

from unittest.mock import MagicMock, patch

from flask import current_app
from invenio_access.permissions import system_identity

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


def test_update_user_from_remote_fetch_urls_match_client(
    app,
    user_factory,
    db,
    requests_mock,
):
    """The HTTP calls use the same Profiles subs / members URLs the client builds."""
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
    """An empty lookup by linked account falls back to fetch by KC username."""
    myuser = user_factory(
        email="fallback@example.org",
        oauth_src="knowledgeCommons",
        oauth_id="sub-fb",
        kc_username="kc_fb_user",
    )
    profile = minimal_profile(
        username="kc_fb_user",
        email="fallback@example.org",
    )
    empty = empty_api_response()
    fetch_mock = MagicMock(side_effect=[empty, profile])

    with patch(
        "invenio_remote_user_data_kcworks.services.service.UserDataAPIClient."
        "fetch_user_profile",
        fetch_mock,
    ):
        with patch(
            "invenio_remote_user_data_kcworks.services.service.CILogonHelpers."
            "update_local_user_data",
        ) as update_mock:
            update_mock.return_value = {"user": {}, "groups": []}
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


def test_update_user_from_remote_remote_service_pass_through_idp(app, user_factory, db):
    """Unknown IdP name is kept as the remote service key."""
    myuser = user_factory(
        email="rawidp@example.org",
        kc_username="myuser",
    )
    remote_in = minimal_api_response(
        "x",
        profile=minimal_profile(
            username="myuser",
            email="rawidp@example.org",
        ),
    )
    with patch(
        "invenio_remote_user_data_kcworks.services.service.CILogonHelpers."
        "update_local_user_data",
    ) as update_mock:
        update_mock.return_value = {"user": {}, "groups": []}
        user_data_service.update_user_from_remote(
            system_identity,
            myuser.id,
            "standalone-idp",
            "remote-x",
            remote_data=remote_in,
        )
    assert update_mock.call_args[0][4] == "standalone-idp"
