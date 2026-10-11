# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""Stop without updating the local user when the remote profile is unusable.

Covers:

- An unauthorized Profiles response stops without updating the local user.
- An empty or unreadable Profiles body after fetch stops without updating
  the local user.

Related coverage elsewhere:

- Missing local user → `test_local_user_missing.py`.
- Skip fetch when a usable profile is already in hand →
  `test_prefetched_skips_fetch.py`.
- How we look up Profiles (URLs, fallback, IdP key) → `test_lookup_path.py`.
"""

from flask import current_app
from invenio_access.permissions import system_identity
from invenio_accounts.models import UserIdentity

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


def test_update_user_from_remote_unauthorized_meta_early_exit(app, user_factory, db):
    """An unauthorized Profiles response stops without updating the local user."""
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
    """An empty or unreadable Profiles body after fetch stops without updating."""
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
