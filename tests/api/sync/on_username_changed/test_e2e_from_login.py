# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""KC username rewrite on records when login-triggered sync renames the user.

Trigger is `login_user` (owned by `on_user_login/`); this file owns the
rename fan-out assertions.

Chain: `login_user` → `do_user_data_update` → rename →
`rewrite_records_for_kc_username_change` → published + draft creators.

Forces Celery eager so the rewrite runs in-process. Narrower coverage of
rewrite helpers / task body: `test_kc_username_propagation.py`.
"""

from flask_login import login_user
from invenio_access.permissions import system_identity
from invenio_accounts.proxies import current_accounts
from invenio_app.celery import celery as invenio_celery
from invenio_rdm_records.proxies import current_rdm_records_service
from invenio_search.proxies import current_search_client
from invenio_search.utils import prefix_index

from tests.fixtures.users import user_data_set


def _creator_kc_usernames(record_dict: dict) -> list[str]:
    """Return kc_username identifier values on creators[0]."""
    identifiers = record_dict["metadata"]["creators"][0]["person_or_org"]["identifiers"]
    return [
        ident["identifier"]
        for ident in identifiers
        if ident.get("scheme") == "kc_username"
    ]


def _os_creator_kc_usernames(record_id: str, *, drafts: bool = False) -> list[str]:
    """Return creators[0] kc_username values from the OpenSearch document."""
    index_alias = prefix_index("rdmrecords-drafts" if drafts else "rdmrecords-records")
    result = current_search_client.search(
        index=index_alias,
        body={
            "size": 1,
            "query": {"term": {"id": record_id}},
        },
    )
    hits = result.get("hits", {}).get("hits", [])
    if not hits:
        return []
    return _creator_kc_usernames(hits[0].get("_source", {}))


def test_login_sync_rename_rewrites_published_and_draft_creators(
    running_app,
    db,
    user_factory,
    minimal_published_record_factory,
    minimal_draft_record_factory,
    search_clear,
    mock_send_remote_api_update_fixture,
    enable_celery_eager,
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

    # Nested eager task commits release into this session's connection; expire
    # so the outer identity map does not keep the pre-login User row.
    db.session.expire_all()

    refreshed = current_accounts.datastore.get_user_by_id(user_id)
    assert refreshed.username == new_kc_username

    current_search_client.indices.refresh(index="*rdmrecords*")
    os_published_identifiers = _os_creator_kc_usernames(
        published_record_id, drafts=False
    )
    os_draft_identifiers = _os_creator_kc_usernames(draft_record_id, drafts=True)
    assert new_kc_username in os_published_identifiers, (
        f"OpenSearch published creators still {os_published_identifiers!r}"
    )
    assert new_kc_username in os_draft_identifiers, (
        f"OpenSearch draft creators still {os_draft_identifiers!r}"
    )

    published_after = current_rdm_records_service.read(
        system_identity, published_record_id
    ).to_dict()
    draft_after = current_rdm_records_service.read_draft(
        system_identity, draft_record_id
    ).to_dict()
    published_identifiers = _creator_kc_usernames(published_after)
    draft_identifiers = _creator_kc_usernames(draft_after)

    assert new_kc_username in published_identifiers
    assert new_kc_username in draft_identifiers
