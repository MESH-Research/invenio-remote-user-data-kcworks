# Copyright (C) 2024-2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Dual USER Names on one ORCID: draft create via records API.

When ORCID resolve lands on USER B while the deposit carries USER A's
`kc_username`, merge is skipped. Names work is queued via post-commit
`TaskOp`, so it cannot roll back the draft parent session.

Historical prompt (prod, 2026-11): sync import into `evegd-blog-posts`
failed with `fk_rdm_drafts_metadata_parent_id_rdm_parents_metadata` after
`CitedNamesUpsertComponent` ran in-process. Two `kcworks-user` Names
rows shared one ORCID; resolve merged the deposit into the wrong USER,
identifier union produced two `kc_username` values, Names
`ValidationError` rolled back the draft session, and the parent was gone
before draft insert. This file pins that shape (anonymized) on
`POST /records`.
"""

from __future__ import annotations

import copy
import json

import pytest
from invenio_access.permissions import system_identity
from invenio_db import db
from invenio_rdm_records.proxies import current_rdm_records_service
from invenio_rdm_records.records.models import RDMParentMetadata
from invenio_records_resources.proxies import current_service_registry
from invenio_search import current_search_client
from invenio_search.utils import prefix_index

from invenio_remote_user_data_kcworks.proxies import current_names_sync_service
from invenio_remote_user_data_kcworks.services.names_sync import NamesSyncService

# Valid ORCID (synthetic; not a real person in this fixture).
SHARED_ORCID = "0000-0002-1825-0097"
PRIMARY_USERNAME = "alpha_user"
OTHER_USERNAME = "beta_user"

# Anonymized deposit-shaped body (prod import shape; vocab ids stay real).
SAMPLE_DRAFT_RECORD = {
    "access": {"record": "public", "files": "public"},
    "files": {
        "enabled": True,
        "default_preview": "lorem-ipsum-post.pdf",
        "entries": {
            "lorem-ipsum-post.md": {"key": "lorem-ipsum-post.md", "size": 100},
            "lorem-ipsum-post.pdf": {"key": "lorem-ipsum-post.pdf", "size": 100},
        },
    },
    "metadata": {
        "resource_type": {"id": "textDocument-blogPost"},
        "title": "Lorem Ipsum Dolor Sit Amet",
        "publication_date": "2026-01-15",
        "publisher": "Quux Publishing",
        "languages": [{"id": "eng"}],
        "creators": [
            {
                "person_or_org": {
                    "type": "personal",
                    "name": "Doe, Jane Q",
                    "family_name": "Doe",
                    "given_name": "Jane Q",
                    "identifiers": [
                        {"identifier": PRIMARY_USERNAME, "scheme": "kc_username"},
                        {"identifier": SHARED_ORCID, "scheme": "orcid"},
                        {
                            "identifier": "jane.q.doe@example.org",
                            "scheme": "email",
                        },
                    ],
                },
                "role": {"id": "author"},
                "affiliations": [
                    {"name": "Example University"},
                    {"name": "Sample Institute"},
                ],
            }
        ],
        "rights": [{"id": "cc-by-4.0"}],
        "identifiers": [
            {
                "identifier": "https://example.org/posts/lorem-ipsum-dolor/",
                "scheme": "url",
            },
            {
                "identifier": "lorem-ipsum-post-001",
                "scheme": "import-recid",
            },
        ],
        "description": (
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do "
            "eiusmod tempor incididunt ut labore et dolore magna aliqua."
        ),
    },
    "custom_fields": {
        "journal:journal": {"title": "Lorem Ipsum Journal"},
        "kcr:publication_url": "https://example.org",
        "imprint:imprint": {"place": "Exampleland"},
        "kcr:ai_usage": {
            "ai_used": False,
            "ai_description": "No generative AI was used for this sample text.",
        },
    },
    "parent": {
        "access": {
            "owned_by": [
                {
                    "full_name": "Doe, Jane Q",
                    "email": "jane.q.doe@example.org",
                    "identifiers": [
                        {"identifier": PRIMARY_USERNAME, "scheme": "kc_username"},
                        {"identifier": SHARED_ORCID, "scheme": "orcid"},
                    ],
                }
            ]
        }
    },
    "pids": {
        "doi": {
            "identifier": "10.1234/lorem.ipsum.repro",
            "provider": "external",
        }
    },
}


def _refresh_names_index() -> None:
    """Force the Names index to be searchable for resolve()."""
    current_search_client.indices.refresh(index=prefix_index("names"))


def _seed_duplicate_orcid_user_names(user_factory, *, primary_token: bool = False):
    """Create two KC users / USER Names rows sharing `SHARED_ORCID`.

    Args:
        user_factory: Fixture that creates local users.
        primary_token: When True, mint a bearer token on the primary user.

    Returns:
        Tuple `(primary_factory_result, other_factory_result)`.
    """
    u_primary = user_factory(
        email="alpha_user@example.org",
        kc_username=PRIMARY_USERNAME,
        orcid=SHARED_ORCID,
        oauth_id="http://cilogon.org/serverE/users/alpha-user",
        token=primary_token,
    )
    u_other = user_factory(
        email="beta_user@example.org",
        kc_username=OTHER_USERNAME,
        orcid=SHARED_ORCID,
        oauth_id="http://cilogon.org/serverE/users/beta-user",
    )
    sync = current_names_sync_service
    assert sync.upsert_name_for_user(u_primary.user) is not None
    assert sync.upsert_name_for_user(u_other.user) is not None
    _refresh_names_index()
    return u_primary, u_other


@pytest.mark.usefixtures(
    "running_app",
    "db",
    "search_clear",
    "enable_celery_eager",
    "mock_send_remote_api_update_fixture",
)
def test_draft_create_with_duplicate_orcid_user_names(
    running_app,
    user_factory,
    headers,
    search_clear,
    monkeypatch,
):
    """POST /records succeeds when ORCID resolve would merge the wrong USER.

    Resolve is pinned to `OTHER_USERNAME` while the deposit names
    `PRIMARY_USERNAME` (prod: wrong USER won ORCID lookup; deposit still
    named the intended account). Merge is skipped; `TaskOp` keeps Names
    off the draft create session. Draft parent must persist.
    """
    u_primary, _u_other = _seed_duplicate_orcid_user_names(
        user_factory, primary_token=True
    )

    names = current_service_registry.get("names")
    wrong_user_record = names.read(system_identity, OTHER_USERNAME).to_dict()
    _original_find = NamesSyncService._find_user_record_by_identifier

    def _resolve_orcid_to_other_user(self, value, scheme, identity=None):
        if scheme == "orcid" and value == SHARED_ORCID:
            return wrong_user_record
        return _original_find(self, value, scheme, identity=identity)

    monkeypatch.setattr(
        NamesSyncService,
        "_find_user_record_by_identifier",
        _resolve_orcid_to_other_user,
    )

    body = copy.deepcopy(SAMPLE_DRAFT_RECORD)
    # Records API create without multipart file upload.
    body["files"] = {"enabled": False}
    # This suite uses `create_api`, so records are at `/records` (no `/api`).
    app = running_app.app
    with app.test_client() as client:
        response = client.post(
            "/records",
            data=json.dumps(body),
            headers={
                **headers,
                "Authorization": f"Bearer {u_primary.allowed_token}",
                "Accept": "application/json",
            },
        )

    assert response.status_code == 201, (
        f"expected 201, got {response.status_code}: {response.get_json()}"
    )
    draft = response.get_json()
    assert draft is not None
    assert draft.get("id")
    # REST `parent.id` is the public PID; the DB PK is the parent UUID.
    draft_item = current_rdm_records_service.read_draft(
        system_identity, draft["id"]
    )
    parent_uuid = draft_item._record.parent.id
    assert db.session.get(RDMParentMetadata, parent_uuid) is not None
