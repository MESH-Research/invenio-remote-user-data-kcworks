# Copyright (C) 2024-2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Service-level tests for username-ingest helpers on `RemoteUserDataService`.

Covers `fetch_subs_profile_for_kc_username`, `find_local_user_by_kc_username`,
and `provision_user_from_members_profile` with real service code (mocked Profiles
HTTP; DB/search fixtures when users are created).

See `tests/api/users/test_ingest_user_by_kc_username.py` for task orchestration
(`do_ingest_user_by_kc_username`) with the service mocked.
"""

from invenio_access.permissions import system_identity
from invenio_accounts.proxies import current_accounts

from invenio_remote_user_data_kcworks.proxies import (
    current_remote_user_data_service as user_data_service,
)
from tests.fixtures.idms import minimal_api_response, minimal_profile


def _subs_by_username_url(base_api_url: str, kc_username: str) -> str:
    return f"{base_api_url}subs/{kc_username}/"


def _members_url(base_api_url: str, kc_username: str) -> str:
    return f"{base_api_url}members/{kc_username}/"


def test_fetch_subs_profile_for_kc_username_uses_subs_endpoint(
    base_app, requests_mock
):
    """Sub lookup hits `GET …/subs/{username}/`."""
    kc_username = "linkeduser"
    base = base_app.config["IDMS_BASE_API_URL"]
    payload = minimal_api_response(
        "http://cilogon.org/serverE/users/linked",
        username=kc_username,
    )
    requests_mock.get(
        _subs_by_username_url(base, kc_username),
        json=payload.model_dump(mode="json"),
    )

    with base_app.app_context():
        out = user_data_service.fetch_subs_profile_for_kc_username(kc_username)

    assert out is not None
    assert out.data[0].sub == "http://cilogon.org/serverE/users/linked"


def test_fetch_subs_profile_returns_none_when_data_empty(base_app, requests_mock):
    """Empty subs list is treated as no linked OAuth subject."""
    kc_username = "nolink"
    base = base_app.config["IDMS_BASE_API_URL"]
    empty = minimal_api_response("unused").model_dump(mode="json")
    empty["data"] = []
    requests_mock.get(_subs_by_username_url(base, kc_username), json=empty)

    with base_app.app_context():
        out = user_data_service.fetch_subs_profile_for_kc_username(kc_username)

    assert out is None


def test_find_local_user_by_kc_username_matches_profile_field(
    app, user_factory, db, requests_mock, search_clear
):
    """Skip helper finds users by `identifier_kc_username`."""
    u = user_factory(
        email="ingest-skip@example.org",
        oauth_id="http://cilogon.org/serverE/users/skip",
        kc_username="skipme",
    )

    with app.app_context():
        found = user_data_service.find_local_user_by_kc_username("skipme")
        missing = user_data_service.find_local_user_by_kc_username("nobody")

    assert found is not None
    assert found.id == u.user.id
    assert missing is None


def test_provision_user_from_members_profile_creates_user(
    app, db, requests_mock, search_clear
):
    """Members-only path creates a user and applies profile fields."""
    kc_username = "newmember"
    base = app.config["IDMS_BASE_API_URL"]
    profile = minimal_profile(
        username=kc_username,
        email="newmember@example.org",
        name="New Member",
    )
    requests_mock.get(
        _members_url(base, kc_username),
        json=profile.model_dump(mode="json"),
    )

    with app.app_context():
        user = user_data_service.provision_user_from_members_profile(
            system_identity,
            kc_username,
        )
        assert user is not None
        user_id = user.id

    db.session.expire_all()
    with app.app_context():
        user = current_accounts.datastore.get_user_by_id(user_id)

    assert user is not None
    assert user.email == "newmember@example.org"
    assert user.user_profile.get("identifier_kc_username") == kc_username
