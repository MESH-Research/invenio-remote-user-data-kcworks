# Copyright (C) 2024-2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Integration tests for the username bulk-ingest workflow.

Exercises `do_ingest_user_by_kc_username` and `do_ingest_profiles_dump` without
mocking the service layer: real Profiles HTTP is stubbed, local users and Names
records are created, and `sync_user_to_names` runs via eager Celery.

Unit/service coverage lives in `test_username_ingest_service.py` and
`test_ingest_user_by_kc_username.py`.
"""

import re

from invenio_access.permissions import system_identity
from invenio_accounts.proxies import current_accounts
from invenio_oauthclient.models import UserIdentity
from invenio_records_resources.proxies import current_service_registry

from invenio_remote_user_data_kcworks.config import KCNamesTag
from invenio_remote_user_data_kcworks.proxies import (
    current_remote_user_data_service as user_data_service,
)
from invenio_remote_user_data_kcworks.tasks import (
    do_ingest_profiles_dump,
    do_ingest_user_by_kc_username,
)
from tests.fixtures.idms import (
    empty_api_response,
    minimal_api_response,
    minimal_profile,
)


def _subs_by_username_url(base_api_url: str, kc_username: str) -> str:
    return f"{base_api_url}subs/{kc_username}/"


def _members_url(base_api_url: str, kc_username: str) -> str:
    return f"{base_api_url}members/{kc_username}/"


def _mock_members_only_profile(
    requests_mock,
    base_api_url: str,
    kc_username: str,
    *,
    email: str,
    name: str = "New Member",
) -> None:
    """Stub empty subs-by-username and a members profile payload."""
    empty = empty_api_response().model_dump(mode="json")
    requests_mock.get(_subs_by_username_url(base_api_url, kc_username), json=empty)
    profile = minimal_profile(username=kc_username, email=email, name=name)
    requests_mock.get(
        _members_url(base_api_url, kc_username),
        json=profile.model_dump(mode="json"),
    )


def _mock_subs_linked_profile(
    requests_mock,
    base_api_url: str,
    kc_username: str,
    *,
    sub: str,
    email: str,
) -> None:
    """Stub subs-by-username with a linked OAuth subject and accept status POSTs."""
    payload = minimal_api_response(sub, username=kc_username, email=email)
    requests_mock.get(
        _subs_by_username_url(base_api_url, kc_username),
        json=payload.model_dump(mode="json"),
    )
    requests_mock.post(
        re.compile(rf"^{re.escape(base_api_url)}members/.+/works/status$"),
        status_code=204,
    )


def _names_record(app, kc_username: str) -> dict:
    """Return the Names vocabulary record for a KC username PID."""
    with app.app_context():
        names = current_service_registry.get("names")
        return names.read(system_identity, kc_username).to_dict()


def test_members_path_creates_user_and_names_record(
    app, db, requests_mock, search_clear
):
    """No linked sub: provision from members, enqueue names sync, no UserIdentity."""
    kc_username = "integ-member"
    email = "integ-member@example.org"
    base = app.config["IDMS_BASE_API_URL"]
    _mock_members_only_profile(
        requests_mock, base, kc_username, email=email, name="Integration Member"
    )

    with app.app_context():
        user_id = do_ingest_user_by_kc_username(kc_username)

    assert user_id is not None
    db.session.expire_all()
    user = current_accounts.datastore.get_user_by_id(user_id)
    assert user.email == email
    assert user.user_profile.get("identifier_kc_username") == kc_username
    assert user.user_profile.get("full_name") == "Integration Member"
    assert UserIdentity.query.filter_by(id_user=user_id, method="cilogon").count() == 0

    names = _names_record(app, kc_username)
    assert names["id"] == kc_username
    assert KCNamesTag.USER in names.get("tags", [])


def test_skips_when_local_user_already_exists(
    app, db, user_factory, requests_mock, search_clear
):
    """Existing `identifier_kc_username` is a no-op; Profiles is not contacted."""
    u = user_factory(
        email="integ-skip@example.org",
        oauth_id="http://cilogon.org/serverE/users/integ-skip",
        kc_username="integ-skip",
    )

    with app.app_context():
        result = do_ingest_user_by_kc_username("integ-skip")

    assert result is None
    assert len(requests_mock.request_history) == 0
    with app.app_context():
        found = user_data_service.find_local_user_by_kc_username("integ-skip")
    assert found is not None
    assert found.id == u.user.id


def test_subs_path_creates_user_with_identity_and_names(
    app, db, requests_mock, search_clear
):
    """Linked subs payload delegates through `do_user_created` (identity + names)."""
    kc_username = "integ-linked"
    sub = "http://cilogon.org/serverE/users/integ-linked"
    email = "integ-linked@example.org"
    base = app.config["IDMS_BASE_API_URL"]
    _mock_subs_linked_profile(requests_mock, base, kc_username, sub=sub, email=email)

    with app.app_context():
        user_id = do_ingest_user_by_kc_username(kc_username)

    assert user_id is not None
    db.session.expire_all()
    user = current_accounts.datastore.get_user_by_id(user_id)
    assert user.email == email
    assert user.user_profile.get("identifier_kc_username") == kc_username

    identity = UserIdentity.query.filter_by(id=sub, method="cilogon").one_or_none()
    assert identity is not None
    assert identity.id_user == user_id

    names = _names_record(app, kc_username)
    assert names["id"] == kc_username
    assert KCNamesTag.USER in names.get("tags", [])


def test_usernames_dump_file_end_to_end(app, db, requests_mock, search_clear, tmp_path):
    """CSV username dump runs the full per-row ingest helper without mocks."""
    kc_username = "integ-dump"
    email = "integ-dump@example.org"
    base = app.config["IDMS_BASE_API_URL"]
    _mock_members_only_profile(requests_mock, base, kc_username, email=email)

    dump_path = tmp_path / "users.csv"
    dump_path.write_text(f"username\n{kc_username}\n")

    with app.app_context():
        stats = do_ingest_profiles_dump(str(dump_path), fmt="usernames")

    assert stats == {
        "rows_seen": 1,
        "processed": 1,
        "skipped": 0,
        "errors": 0,
    }
    with app.app_context():
        found = user_data_service.find_local_user_by_kc_username(kc_username)
    assert found is not None
    assert found.email == email

    names = _names_record(app, kc_username)
    assert names["id"] == kc_username
