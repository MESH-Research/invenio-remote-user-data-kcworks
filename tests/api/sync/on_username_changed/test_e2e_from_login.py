# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""KC username rewrite on records when login-triggered sync renames the user.

Trigger is `login_user` (owned by `on_user_login/`); this file owns the
rename fan-out assertions.

Covers:

- Published personal creator `kc_username` rewritten (republished).
- Draft personal creator `kc_username` patched in place.

Unit / service coverage of rewrite helpers:
`test_kc_username_propagation.py`.
"""

import time

from flask_login import login_user
from invenio_access.permissions import system_identity
from invenio_accounts.proxies import current_accounts
from invenio_rdm_records.proxies import current_rdm_records_service
from invenio_search.proxies import current_search_client

from tests.fixtures.users import user_data_set


def _creator_kc_usernames(record_dict: dict) -> list[str]:
    """Return kc_username identifier values on creators[0]."""
    identifiers = record_dict["metadata"]["creators"][0]["person_or_org"]["identifiers"]
    return [
        ident["identifier"]
        for ident in identifiers
        if ident.get("scheme") == "kc_username"
    ]


def test_login_sync_rename_rewrites_published_and_draft_creators(
    running_app,
    db,
    user_factory,
    minimal_published_record_factory,
    minimal_draft_record_factory,
    search_clear,
    celery_worker,
    mock_send_remote_api_update_fixture,
):
    """Login sync that changes kc_username rewrites published + draft creators."""
    new_data_payload = user_data_set["user1"]
    new_kc_username = new_data_payload["kc_username"]

    u = user_factory(
        email="originalemail@kcommons.org",
        oauth_src="cilogon",
        oauth_id=new_data_payload["oauth_id"],
        kc_username="beforesync",
        new_remote_data=new_data_payload,
    )
    user_id = u.user.id
    assert u.user.username == "beforesync"

    creator_with_old_username = {
        "person_or_org": {
            "family_name": "Doe",
            "given_name": "Jane",
            "name": "Doe, Jane",
            "type": "personal",
            "identifiers": [
                {"scheme": "kc_username", "identifier": "beforesync"},
            ],
        },
    }
    published_record = minimal_published_record_factory(
        metadata_updates={"metadata|creators|0": creator_with_old_username},
    )
    draft_record = minimal_draft_record_factory(
        metadata={
            "pids": {},
            "access": {"record": "public", "files": "public"},
            "files": {"enabled": False},
            "metadata": {
                "creators": [creator_with_old_username],
                "publication_date": "2020-06-01",
                "publisher": "Acme Inc",
                "resource_type": {"id": "image-photograph"},
                "title": "Draft cited by oldname",
            },
            "custom_fields": {},
        },
    )
    published_record_id = published_record.id
    draft_record_id = draft_record.id
    current_search_client.indices.refresh(index="*rdmrecords*")

    login_user(u.user)

    # Login sync is ``do_user_data_update.delay`` then nested
    # ``rewrite_records_for_kc_username_change.delay`` (suite is non-eager).
    deadline = time.time() + 30
    published_identifiers: list[str] = []
    draft_identifiers: list[str] = []
    while time.time() < deadline:
        db.session.expire_all()
        refreshed = current_accounts.datastore.get_user_by_id(user_id)
        if refreshed is not None and refreshed.username == new_kc_username:
            current_search_client.indices.refresh(index="*rdmrecords*")
            published_after = current_rdm_records_service.read(
                system_identity, published_record_id
            ).to_dict()
            draft_after = current_rdm_records_service.read_draft(
                system_identity, draft_record_id
            ).to_dict()
            published_identifiers = _creator_kc_usernames(published_after)
            draft_identifiers = _creator_kc_usernames(draft_after)
            if (
                new_kc_username in published_identifiers
                and new_kc_username in draft_identifiers
            ):
                break
        time.sleep(0.25)
    else:
        raise AssertionError(
            "Timed out waiting for login sync rename rewrite; "
            f"published={published_identifiers!r} draft={draft_identifiers!r}"
        )

    assert new_kc_username in published_identifiers
    assert new_kc_username in draft_identifiers
