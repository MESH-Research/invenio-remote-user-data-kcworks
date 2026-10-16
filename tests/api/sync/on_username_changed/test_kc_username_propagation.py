# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2024-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""When someone’s KC username changes, fix up records and names.

Covers:

- Old username in record author/contributor IDs gets rewritten.
- Published records get edited/republished; drafts get patched.
- Stale name entries get cleaned up.
- Rewrite work only kicks off when the username actually changed.
- Task body (sync `.run()`) against real published/draft records.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from invenio_access.permissions import system_identity
from invenio_rdm_records.proxies import current_rdm_records_service
from invenio_search.proxies import current_search_client

from invenio_remote_user_data_kcworks.config import KCNamesTag
from invenio_remote_user_data_kcworks.proxies import (
    current_record_kc_username_sync_service,
    current_remote_user_data_service,
)
from invenio_remote_user_data_kcworks.services.names_sync import NamesSyncService
from invenio_remote_user_data_kcworks.services.record_username_sync import (
    RecordKcUsernameSyncService,
)
from invenio_remote_user_data_kcworks.tasks import (
    rewrite_records_for_kc_username_change,
)
from invenio_remote_user_data_kcworks.types.profiles_api import APIResponse
from invenio_remote_user_data_kcworks.utils.record_metadata import rewrite_kc_username
from tests.fixtures.idms import minimal_api_response, minimal_profile

# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _personal_creator(
    family: str,
    given: str = "",
    *,
    kc_username: str | None = None,
    orcid: str | None = None,
) -> dict[str, Any]:
    """Build a personal-type creator/contributor entry.

    Returns:
        A dict shaped like a single `metadata.creators[*]` or
        `metadata.contributors[*]` entry.
    """
    identifiers: list[dict[str, str]] = []
    if kc_username:
        identifiers.append({"scheme": "kc_username", "identifier": kc_username})
    if orcid:
        identifiers.append({"scheme": "orcid", "identifier": orcid})
    person: dict[str, Any] = {
        "type": "personal",
        "family_name": family,
        "given_name": given,
    }
    if identifiers:
        person["identifiers"] = identifiers
    return {"person_or_org": person}


def _org_creator(name: str, *, kc_username: str | None = None) -> dict[str, Any]:
    """Build an organizational creator (should be ignored by rewriter).

    Returns:
        A dict shaped like an organizational creator entry.
    """
    person: dict[str, Any] = {"type": "organizational", "name": name}
    if kc_username:
        person["identifiers"] = [
            {"scheme": "kc_username", "identifier": kc_username}
        ]
    return {"person_or_org": person}


# ---------------------------------------------------------------------------
# Unit tests: `rewrite_kc_username`
# ---------------------------------------------------------------------------


class TestRewriteKcUsername:
    """Pure-function tests for `rewrite_kc_username`."""

    def test_rewrites_in_creators(self):
        """A matching creator identifier is rewritten and the call returns True."""
        metadata = {
            "creators": [_personal_creator("Doe", "Jane", kc_username="oldname")],
            "contributors": [],
        }
        changed = rewrite_kc_username(
            metadata, old_username="oldname", new_username="newname"
        )
        assert changed is True
        identifier = metadata["creators"][0]["person_or_org"]["identifiers"][0]
        assert identifier == {"scheme": "kc_username", "identifier": "newname"}

    def test_rewrites_in_contributors(self):
        """A matching contributor identifier is rewritten."""
        metadata = {
            "creators": [],
            "contributors": [
                _personal_creator("Doe", "Jane", kc_username="oldname"),
            ],
        }
        changed = rewrite_kc_username(
            metadata, old_username="oldname", new_username="newname"
        )
        assert changed is True
        identifier = metadata["contributors"][0]["person_or_org"]["identifiers"][0]
        assert identifier == {"scheme": "kc_username", "identifier": "newname"}

    def test_rewrites_in_both_lists_simultaneously(self):
        """Creator + contributor matches both rewrite, return True."""
        metadata = {
            "creators": [_personal_creator("A", kc_username="oldname")],
            "contributors": [_personal_creator("B", kc_username="oldname")],
        }
        changed = rewrite_kc_username(
            metadata, old_username="oldname", new_username="newname"
        )
        assert changed is True
        assert (
            metadata["creators"][0]["person_or_org"]["identifiers"][0]["identifier"]
            == "newname"
        )
        assert (
            metadata["contributors"][0]["person_or_org"]["identifiers"][0][
                "identifier"
            ]
            == "newname"
        )

    def test_ignores_non_personal_entries(self):
        """An organizational entry with a coincidental kc_username is left alone."""
        metadata = {
            "creators": [_org_creator("ACME Corp.", kc_username="oldname")],
            "contributors": [],
        }
        changed = rewrite_kc_username(
            metadata, old_username="oldname", new_username="newname"
        )
        assert changed is False
        identifier = metadata["creators"][0]["person_or_org"]["identifiers"][0]
        assert identifier["identifier"] == "oldname"

    def test_ignores_other_schemes(self):
        """An ORCID identifier with the same string value is not rewritten."""
        metadata = {
            "creators": [
                _personal_creator("Doe", "Jane", orcid="oldname"),
            ],
            "contributors": [],
        }
        changed = rewrite_kc_username(
            metadata, old_username="oldname", new_username="newname"
        )
        assert changed is False
        identifier = metadata["creators"][0]["person_or_org"]["identifiers"][0]
        assert identifier == {"scheme": "orcid", "identifier": "oldname"}

    def test_no_op_when_no_match(self):
        """Returns False when no kc_username identifier matches `old_username`."""
        metadata = {
            "creators": [_personal_creator("Doe", "Jane", kc_username="someoneelse")],
            "contributors": [],
        }
        changed = rewrite_kc_username(
            metadata, old_username="oldname", new_username="newname"
        )
        assert changed is False

    def test_no_op_when_old_equals_new(self):
        """Returns False when old and new usernames are equal (defensive)."""
        metadata = {
            "creators": [_personal_creator("Doe", "Jane", kc_username="x")],
            "contributors": [],
        }
        changed = rewrite_kc_username(
            metadata, old_username="x", new_username="x"
        )
        assert changed is False

    def test_no_op_when_username_blank(self):
        """Returns False if either username is empty."""
        metadata = {
            "creators": [_personal_creator("Doe", "Jane", kc_username="oldname")],
            "contributors": [],
        }
        assert (
            rewrite_kc_username(metadata, old_username="", new_username="newname")
            is False
        )
        assert (
            rewrite_kc_username(metadata, old_username="oldname", new_username="")
            is False
        )

    def test_no_op_when_metadata_not_dict(self):
        """Defensive: non-dict input returns False without raising."""
        assert (
            rewrite_kc_username(None, old_username="x", new_username="y")  # type: ignore[arg-type]
            is False
        )

    def test_handles_missing_identifiers_list(self):
        """Personal entries without identifiers are silently skipped."""
        metadata = {
            "creators": [{"person_or_org": {"type": "personal", "family_name": "X"}}],
            "contributors": [],
        }
        assert (
            rewrite_kc_username(
                metadata, old_username="oldname", new_username="newname"
            )
            is False
        )


# ---------------------------------------------------------------------------
# Service tests: RecordKcUsernameSyncService
# ---------------------------------------------------------------------------


@pytest.fixture()
def sync_service(base_app) -> RecordKcUsernameSyncService:
    """Construct a sync service against the pytest-invenio `base_app`.

    Returns:
        A `RecordKcUsernameSyncService` bound to the test app.
    """
    return RecordKcUsernameSyncService(base_app)


def _make_draft_item(draft_id: str, metadata: dict[str, Any]):
    """Return a duck-typed RecordItem for a freshly-edited draft."""
    item = MagicMock()
    item.id = draft_id
    item.data = {"id": draft_id, "metadata": metadata}
    return item


def _make_scan_hit(record_id: str, metadata: dict[str, Any]):
    """Return a duck-typed search hit from `dsl.Search(...).scan()`."""
    hit = MagicMock()
    hit.to_dict.return_value = {"id": record_id, "metadata": metadata}
    return hit


def _make_search_obj(*hits: MagicMock) -> MagicMock:
    """Return a Search DSL mock that chains `.filter()` and yields scan hits."""
    search_obj = MagicMock()
    search_obj.filter.return_value = search_obj
    search_obj.scan.return_value = iter(hits)
    return search_obj


_SEARCH_PATCH = (
    "invenio_remote_user_data_kcworks.services.record_username_sync.dsl.Search"
)
_RECORDS_PATCH = (
    "invenio_remote_user_data_kcworks.services.record_username_sync."
    "current_rdm_records_service"
)


class TestRewritePublished:
    """`rewrite()` (published phase) scans, edits, updates, and publishes."""

    def test_noop_when_old_equals_new(self, sync_service):
        """Early return: no scan, no edit, no publish, zero stats."""
        records_mock = MagicMock(name="current_rdm_records_service")
        with (
            patch(_RECORDS_PATCH, new=records_mock),
            patch(_SEARCH_PATCH) as search_cls,
        ):
            stats = sync_service.rewrite("same", "same")
        assert stats == {
            "matched": 0,
            "updated": 0,
            "failed": 0,
            "drafts_left_uncommitted": 0,
        }
        search_cls.assert_not_called()
        records_mock.edit.assert_not_called()

    def test_happy_path_published_record_is_edited_and_republished(
        self, base_app, sync_service
    ):
        """Each match: scan -> edit -> update_draft -> publish."""
        edited_metadata = {
            "creators": [_personal_creator("Doe", "Jane", kc_username="oldname")],
            "contributors": [],
        }
        search_obj = _make_search_obj(_make_scan_hit("rec-1", edited_metadata))
        draft_item = _make_draft_item("rec-1", edited_metadata)

        records_mock = MagicMock()
        records_mock.edit.return_value = draft_item

        with base_app.app_context():
            with (
                patch(_RECORDS_PATCH, records_mock),
                patch(_SEARCH_PATCH, return_value=search_obj) as search_cls,
            ):
                stats = sync_service.rewrite("oldname", "newname")

        search_cls.assert_called_once()
        assert "rdmrecords-records" in search_cls.call_args.kwargs["index"]
        search_obj.filter.assert_called_once()
        records_mock.edit.assert_called_once()
        records_mock.update_draft.assert_called_once()
        records_mock.publish.assert_called_once()

        # The metadata passed to update_draft must carry the rewritten value.
        update_call = records_mock.update_draft.call_args
        patched_data = update_call[0][2]
        assert (
            patched_data["metadata"]["creators"][0]["person_or_org"]["identifiers"][
                0
            ]["identifier"]
            == "newname"
        )
        assert stats == {
            "matched": 1,
            "updated": 1,
            "failed": 0,
            "drafts_left_uncommitted": 0,
        }

    def test_false_positive_match_is_filtered_before_edit(self, base_app, sync_service):
        """If the scan hit is not a kc_username match, no draft is opened."""
        # The hit's metadata carries `oldname` only on an ORCID scheme, so
        # `_scan_ids` filters it before `edit()` can open a draft.
        source_metadata = {
            "creators": [_personal_creator("Doe", "Jane", orcid="oldname")],
            "contributors": [],
        }
        search_obj = _make_search_obj(_make_scan_hit("rec-1", source_metadata))
        records_mock = MagicMock()

        with base_app.app_context():
            with (
                patch(_RECORDS_PATCH, records_mock),
                patch(_SEARCH_PATCH, return_value=search_obj),
            ):
                stats = sync_service.rewrite("oldname", "newname")

        records_mock.edit.assert_not_called()
        records_mock.update_draft.assert_not_called()
        records_mock.publish.assert_not_called()
        assert stats == {
            "matched": 0,
            "updated": 0,
            "failed": 0,
            "drafts_left_uncommitted": 0,
        }

    def test_per_record_failure_is_logged_and_counted(self, base_app, sync_service):
        """A failure on one record does not stop the loop or escape the service."""
        good_metadata = {
            "creators": [_personal_creator("A", kc_username="oldname")],
            "contributors": [],
        }
        search_obj = _make_search_obj(
            _make_scan_hit("rec-good", good_metadata),
            _make_scan_hit("rec-bad", good_metadata),
        )
        records_mock = MagicMock()

        def _edit(identity, record_id):
            if record_id == "rec-bad":
                raise RuntimeError("edit blew up")
            return _make_draft_item(record_id, good_metadata)

        records_mock.edit.side_effect = _edit

        with base_app.app_context():
            with (
                patch(_RECORDS_PATCH, records_mock),
                patch(_SEARCH_PATCH, return_value=search_obj),
            ):
                stats = sync_service.rewrite("oldname", "newname")

        assert stats == {
            "matched": 2,
            "updated": 1,
            "failed": 1,
            "drafts_left_uncommitted": 0,
        }


class TestRewriteDrafts:
    """`rewrite(..., drafts=True)` patches drafts with update_draft, no publish."""

    def test_happy_path_draft_is_patched_without_publish(
        self, base_app, sync_service
    ):
        """One scanned draft, one update_draft call, zero publish calls."""
        edited_metadata = {
            "creators": [_personal_creator("Doe", "Jane", kc_username="oldname")],
            "contributors": [],
        }
        draft_item = _make_draft_item("draft-1", edited_metadata)
        search_obj = _make_search_obj(_make_scan_hit("draft-1", edited_metadata))

        records_mock = MagicMock()
        records_mock.read_draft.return_value = draft_item

        with base_app.app_context():
            with (
                patch(_RECORDS_PATCH, records_mock),
                patch(_SEARCH_PATCH, return_value=search_obj) as search_cls,
            ):
                stats = sync_service.rewrite("oldname", "newname", drafts=True)

        assert "rdmrecords-drafts" in search_cls.call_args.kwargs["index"]
        search_obj.filter.assert_called_once()

        records_mock.update_draft.assert_called_once()
        records_mock.publish.assert_not_called()
        update_call = records_mock.update_draft.call_args
        patched_data = update_call[0][2]
        assert (
            patched_data["metadata"]["creators"][0]["person_or_org"]["identifiers"][
                0
            ]["identifier"]
            == "newname"
        )
        assert stats == {"matched": 1, "updated": 1, "failed": 0, "no_op": 0}


# ---------------------------------------------------------------------------
# NamesSyncService.prune_stale_user_records
# ---------------------------------------------------------------------------


def _user(*, user_id: int = 7, kc_username: str = "newname"):
    """Duck-typed user shaped like `invenio_accounts.models.User`.

    Returns:
        A `SimpleNamespace` with `id`, `username`, `email`, and
        `user_profile` populated.
    """
    return SimpleNamespace(
        id=user_id,
        username=kc_username,
        email="x@example.org",
        user_profile={"identifier_kc_username": kc_username},
    )


class TestPruneStaleUserRecords:
    """Names prune: delete USER-tagged records at PIDs other than current."""

    def test_deletes_old_pid_keeps_new(self, base_app):
        """Two USER records for one user: old PID gets deleted, new PID kept."""
        service = NamesSyncService(base_app)
        names = MagicMock()

        hits = {
            "hits": {
                "hits": [
                    {
                        "id": "oldname",
                        "tags": [KCNamesTag.USER],
                        "props": {"kcworks_user_id": "7"},
                    },
                    {
                        "id": "newname",
                        "tags": [KCNamesTag.USER],
                        "props": {"kcworks_user_id": "7"},
                    },
                ],
            },
        }
        search_result = MagicMock()
        search_result.to_dict.return_value = hits
        names.search.return_value = search_result

        with base_app.app_context():
            with patch.object(
                NamesSyncService,
                "names_service",
                new=property(lambda self: names),
            ):
                deleted = service.prune_stale_user_records(_user(user_id=7))

        assert deleted == ["oldname"]
        names.delete.assert_called_once()
        # `delete(identity, pid)` second positional arg is the PID.
        assert names.delete.call_args[0][1] == "oldname"

    def test_ignores_cited_tagged_records_even_with_matching_user_id(
        self, base_app
    ):
        """`kcworks-cited` records carrying the same user id are not deleted."""
        service = NamesSyncService(base_app)
        names = MagicMock()

        hits = {
            "hits": {
                "hits": [
                    {
                        "id": "0000-0001-2345-6789",
                        "tags": [KCNamesTag.CITED],
                        "props": {"kcworks_user_id": "7"},
                    },
                ],
            },
        }
        search_result = MagicMock()
        search_result.to_dict.return_value = hits
        names.search.return_value = search_result

        with base_app.app_context():
            with patch.object(
                NamesSyncService,
                "names_service",
                new=property(lambda self: names),
            ):
                deleted = service.prune_stale_user_records(_user(user_id=7))

        assert deleted == []
        names.delete.assert_not_called()

    def test_returns_empty_when_user_has_no_current_username(self, base_app):
        """No current `identifier_kc_username` → no search, no delete."""
        service = NamesSyncService(base_app)
        names = MagicMock()
        u = SimpleNamespace(
            id=7,
            username="",
            email="x@example.org",
            user_profile={"identifier_kc_username": ""},
        )

        with base_app.app_context():
            with patch.object(
                NamesSyncService,
                "names_service",
                new=property(lambda self: names),
            ):
                deleted = service.prune_stale_user_records(u)

        assert deleted == []
        names.search.assert_not_called()
        names.delete.assert_not_called()

    def test_filters_out_records_whose_props_user_id_disagrees(self, base_app):
        """Defensive: a hit whose props.kcworks_user_id doesn't match is skipped."""
        service = NamesSyncService(base_app)
        names = MagicMock()

        hits = {
            "hits": {
                "hits": [
                    {
                        "id": "oldname",
                        "tags": [KCNamesTag.USER],
                        "props": {"kcworks_user_id": "999"},
                    },
                ],
            },
        }
        search_result = MagicMock()
        search_result.to_dict.return_value = hits
        names.search.return_value = search_result

        with base_app.app_context():
            with patch.object(
                NamesSyncService,
                "names_service",
                new=property(lambda self: names),
            ):
                deleted = service.prune_stale_user_records(_user(user_id=7))

        assert deleted == []
        names.delete.assert_not_called()


# ---------------------------------------------------------------------------
# Service trigger: `RemoteUserDataService.update_user_from_remote`
# ---------------------------------------------------------------------------


class TestUpdateUserFromRemoteDispatch:
    """When remote sync applies a profile, enqueue record rewrite only on rename.

    `update_user_from_remote` compares the local `identifier_kc_username` to
    the username on the transformed remote profile (`new_data`). A change
    queues `rewrite_records_for_kc_username_change`; an unchanged username
    does not, even if other fields (e.g. email) update.
    """

    def test_dispatches_task_when_username_changes(self, app, user_factory, db):
        """Remote username rename enqueues `rewrite_records_for_kc_username_change`."""
        fixture = user_factory(
            email="dispatched@example.org",
            kc_username="oldname",
            oauth_src="cilogon",
            oauth_id="sub-d",
        )
        remote_in: APIResponse = minimal_api_response(
            "sub-d",
            profile=minimal_profile(
                username="newname",
                email="dispatched@example.org",
            ),
        )

        with patch(
            "invenio_remote_user_data_kcworks.tasks."
            "rewrite_records_for_kc_username_change.delay"
        ) as delay_mock:
            current_remote_user_data_service.update_user_from_remote(
                system_identity,
                fixture.user.id,
                "knowledgeCommons",
                "sub-d",
                remote_data=remote_in,
            )

        delay_mock.assert_called_once_with(fixture.user.id, "oldname", "newname")

    def test_no_dispatch_when_username_unchanged(self, app, user_factory, db):
        """Email-only remote update: same kc_username → no rewrite task."""
        fixture = user_factory(
            email="unchanged@example.org",
            kc_username="samename",
            oauth_src="cilogon",
            oauth_id="sub-u",
        )
        remote_in: APIResponse = minimal_api_response(
            "sub-u",
            profile=minimal_profile(
                username="samename",
                email="new-email@example.org",
            ),
        )

        with patch(
            "invenio_remote_user_data_kcworks.tasks."
            "rewrite_records_for_kc_username_change.delay"
        ) as delay_mock:
            current_remote_user_data_service.update_user_from_remote(
                system_identity,
                fixture.user.id,
                "knowledgeCommons",
                "sub-u",
                remote_data=remote_in,
            )

        delay_mock.assert_not_called()


# ---------------------------------------------------------------------------
# Task body (sync): real records / service persistence
# ---------------------------------------------------------------------------


def _creator_kc_usernames(record_dict: dict[str, Any]) -> list[str]:
    """Return `kc_username` identifier values on `creators[0]`.

    Returns:
        Identifier strings for the first creator's `kc_username` scheme.
    """
    identifiers = record_dict["metadata"]["creators"][0]["person_or_org"]["identifiers"]
    return [
        ident["identifier"]
        for ident in identifiers
        if ident.get("scheme") == "kc_username"
    ]


def _seed_published_and_draft_with_kc_username(
    *,
    old_username: str,
    title: str,
    minimal_published_record_factory,
    minimal_draft_record_factory,
) -> tuple[str, str]:
    """Create published + draft records citing `old_username`, refresh search.

    Returns:
        `(published_id, draft_id)`.
    """
    creator = {
        "person_or_org": {
            "family_name": "Doe",
            "given_name": "Jane",
            "name": "Doe, Jane",
            "type": "personal",
            "identifiers": [
                {"scheme": "kc_username", "identifier": old_username},
            ],
        },
    }
    published = minimal_published_record_factory(
        metadata_updates={"metadata|creators|0": creator},
    )
    draft = minimal_draft_record_factory(
        metadata={
            "pids": {},
            "access": {"record": "public", "files": "public"},
            "files": {"enabled": False},
            "metadata": {
                "creators": [creator],
                "publication_date": "2020-06-01",
                "publisher": "Acme Inc",
                "resource_type": {"id": "image-photograph"},
                "title": title,
            },
            "custom_fields": {},
        },
    )
    current_search_client.indices.refresh(index="*rdmrecords*")
    return published.id, draft.id


def _assert_creators_rewritten(
    *,
    published_id: str,
    draft_id: str,
    new_username: str,
    stats: dict[str, Any],
) -> None:
    """Assert RDM service reads show `new_username` on published + draft."""
    published_after = current_rdm_records_service.read(
        system_identity, published_id
    ).to_dict()
    draft_after = current_rdm_records_service.read_draft(
        system_identity, draft_id
    ).to_dict()

    assert new_username in _creator_kc_usernames(published_after), (
        f"published creators still {_creator_kc_usernames(published_after)!r}; "
        f"stats={stats!r}"
    )
    assert new_username in _creator_kc_usernames(draft_after), (
        f"draft creators still {_creator_kc_usernames(draft_after)!r}; "
        f"stats={stats!r}"
    )


class TestRewriteRecordsTaskBody:
    """Run `rewrite_records_for_kc_username_change` body against real records.

    Isolates the Celery task from login/dispatch: call `.run()` so the body
    executes in-process, then assert RDM service reads show the new username.
    """

    def test_run_rewrites_published_and_draft_creators(
        self,
        running_app,
        db,
        user_factory,
        minimal_published_record_factory,
        minimal_draft_record_factory,
        search_clear,
    ):
        """Synchronous task body updates published + draft creator usernames."""
        old_username = "taskbodyold"
        new_username = "taskbodynew"

        user = user_factory(
            email="taskbody@example.org",
            kc_username=old_username,
            oauth_src="cilogon",
            oauth_id="sub-task-body",
        )
        published_id, draft_id = _seed_published_and_draft_with_kc_username(
            old_username=old_username,
            title="Draft for task-body rewrite",
            minimal_published_record_factory=minimal_published_record_factory,
            minimal_draft_record_factory=minimal_draft_record_factory,
        )

        summary = rewrite_records_for_kc_username_change.run(
            user.user.id,
            old_username,
            new_username,
            prune_names=False,
        )

        assert summary["errors"] == 0
        assert summary["records"]["published"]["updated"] >= 1
        assert summary["records"]["drafts"]["updated"] >= 1

        # Task nests app_context; drop outer identity-map so reads rehit the DB.
        db.session.expire_all()

        _assert_creators_rewritten(
            published_id=published_id,
            draft_id=draft_id,
            new_username=new_username,
            stats=summary["records"],
        )


class TestRewriteAllService:
    """Call `RecordKcUsernameSyncService.rewrite_all` against real records.

    Sister to `TestRewriteRecordsTaskBody`: same seed/asserts, no Celery task.
    """

    def test_rewrite_all_rewrites_published_and_draft_creators(
        self,
        running_app,
        db,
        minimal_published_record_factory,
        minimal_draft_record_factory,
        search_clear,
    ):
        """Direct `rewrite_all` updates published + draft creator usernames."""
        old_username = "rewriteallold"
        new_username = "rewriteallnew"

        published_id, draft_id = _seed_published_and_draft_with_kc_username(
            old_username=old_username,
            title="Draft for rewrite_all",
            minimal_published_record_factory=minimal_published_record_factory,
            minimal_draft_record_factory=minimal_draft_record_factory,
        )

        stats = current_record_kc_username_sync_service.rewrite_all(
            old_username, new_username
        )

        assert stats["errors"] == 0
        assert stats["published"]["updated"] >= 1
        assert stats["drafts"]["updated"] >= 1
        _assert_creators_rewritten(
            published_id=published_id,
            draft_id=draft_id,
            new_username=new_username,
            stats=stats,
        )
