# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2024-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Tests for propagation of kc_username renames through records and Names.

Three layers are exercised here, with progressively more wiring mocked:

1. **Unit** — `rewrite_kc_username` walks creators+contributors in a
   metadata dict and rewrites only personal-type, `kc_username`-scheme
   entries.
2. **Service** — `RecordKcUsernameSyncService.rewrite` orchestrates the
   edit/update/publish (or update_draft) loop in both phases via the
   `drafts` flag; OS / RDM-records calls are mocked so we can assert
   call shapes without spinning up search.
3. **Names prune** — `NamesSyncService.prune_stale_user_records` deletes
   only USER-tagged records whose PID differs from the user's current
   kc_username.
4. **Trigger** — `RemoteUserDataService.update_user_from_remote` dispatches
   `rewrite_records_for_kc_username_change.delay` exactly when the
   committed username differs from the pre-update value.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from invenio_remote_user_data_kcworks.config import KCNamesTag
from invenio_remote_user_data_kcworks.services.names_sync import NamesSyncService
from invenio_remote_user_data_kcworks.services.record_username_sync import (
    RecordKcUsernameSyncService,
)
from invenio_remote_user_data_kcworks.utils.record_metadata import rewrite_kc_username

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
    item.to_dict.return_value = {"id": draft_id, "metadata": metadata}
    return item


class TestRewritePublished:
    """`rewrite()` (published phase) scans, edits, updates, and publishes."""

    def test_noop_when_old_equals_new(self, sync_service):
        """Early return: no scan, no edit, no publish, zero stats."""
        records_mock = MagicMock(name="current_rdm_records_service")
        with patch(
            "invenio_remote_user_data_kcworks.services.record_username_sync."
            "current_rdm_records_service",
            new=records_mock,
        ):
            stats = sync_service.rewrite("same", "same")
        assert stats == {
            "matched": 0,
            "updated": 0,
            "failed": 0,
            "drafts_left_uncommitted": 0,
        }
        records_mock.scan.assert_not_called()

    def test_happy_path_published_record_is_edited_and_republished(
        self, base_app, sync_service
    ):
        """Each match: scan -> edit -> update_draft -> publish."""
        hit = {"id": "rec-1"}
        scan_result = MagicMock()
        scan_result.hits = iter([hit])

        edited_metadata = {
            "creators": [_personal_creator("Doe", "Jane", kc_username="oldname")],
            "contributors": [],
        }
        draft_item = _make_draft_item("rec-1", edited_metadata)

        records_mock = MagicMock()
        records_mock.scan.return_value = scan_result
        records_mock.edit.return_value = draft_item

        with base_app.app_context():
            with patch(
                "invenio_remote_user_data_kcworks.services.record_username_sync."
                "current_rdm_records_service",
                records_mock,
            ):
                stats = sync_service.rewrite("oldname", "newname")

        records_mock.scan.assert_called_once()
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

    def test_false_positive_match_leaves_draft_in_place(self, base_app, sync_service):
        """If the rewriter finds nothing to change, no update/publish happens."""
        hit = {"id": "rec-1"}
        scan_result = MagicMock()
        scan_result.hits = iter([hit])

        # The hit's metadata carries `oldname` only on an ORCID scheme, so
        # the rewriter returns False. The draft must NOT be published.
        edited_metadata = {
            "creators": [_personal_creator("Doe", "Jane", orcid="oldname")],
            "contributors": [],
        }
        draft_item = _make_draft_item("rec-1", edited_metadata)

        records_mock = MagicMock()
        records_mock.scan.return_value = scan_result
        records_mock.edit.return_value = draft_item

        with base_app.app_context():
            with patch(
                "invenio_remote_user_data_kcworks.services.record_username_sync."
                "current_rdm_records_service",
                records_mock,
            ):
                stats = sync_service.rewrite("oldname", "newname")

        records_mock.edit.assert_called_once()
        records_mock.update_draft.assert_not_called()
        records_mock.publish.assert_not_called()
        assert stats == {
            "matched": 1,
            "updated": 0,
            "failed": 0,
            "drafts_left_uncommitted": 1,
        }

    def test_per_record_failure_is_logged_and_counted(self, base_app, sync_service):
        """A failure on one record does not stop the loop or escape the service."""
        hits = [{"id": "rec-good"}, {"id": "rec-bad"}]
        scan_result = MagicMock()
        scan_result.hits = iter(hits)

        good_metadata = {
            "creators": [_personal_creator("A", kc_username="oldname")],
            "contributors": [],
        }
        records_mock = MagicMock()
        records_mock.scan.return_value = scan_result

        def _edit(identity, record_id):
            if record_id == "rec-bad":
                raise RuntimeError("edit blew up")
            return _make_draft_item(record_id, good_metadata)

        records_mock.edit.side_effect = _edit

        with base_app.app_context():
            with patch(
                "invenio_remote_user_data_kcworks.services.record_username_sync."
                "current_rdm_records_service",
                records_mock,
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

        records_mock = MagicMock()
        records_mock.read_draft.return_value = draft_item

        search_obj = MagicMock()
        search_obj.query.return_value = search_obj
        search_obj.scan.return_value = iter([{"id": "draft-1"}])

        with base_app.app_context():
            with patch(
                "invenio_remote_user_data_kcworks.services.record_username_sync."
                "current_rdm_records_service",
                records_mock,
            ):
                with patch(
                    "invenio_remote_user_data_kcworks.services.record_username_sync."
                    "Search",
                    return_value=search_obj,
                ):
                    stats = sync_service.rewrite(
                        "oldname", "newname", drafts=True
                    )

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
    """Did `update_user_from_remote` dispatch the rewrite task?"""

    def _patch_helpers(
        self,
        *,
        old_kc: str | None,
        new_kc: str | None,
    ):
        """Set up the helper mocks for one dispatch scenario.

        Dispatch is now driven entirely by the sparse `user_changes`
        diff returned by `calculate_user_changes`. When `new_kc` differs
        from `old_kc`, the mocked diff carries
        `user_profile.identifier_kc_username = new_kc` (mirroring what
        `_diff_between_nested_dicts` would produce); otherwise the diff
        is empty and no dispatch should fire. `update_local_user_data`
        is stubbed to a no-op because it does not influence the
        dispatch decision under the new logic.

        Returns:
            An `ExitStack` context manager holding the helper patches.
        """
        from contextlib import ExitStack

        stack = ExitStack()
        stack.enter_context(
            patch(
                "invenio_remote_user_data_kcworks.services.service.CILogonHelpers."
                "calculate_group_changes",
                return_value={
                    "added_groups": [],
                    "dropped_groups": [],
                    "unchanged_groups": [],
                },
            )
        )

        if new_kc and new_kc != old_kc:
            user_changes = {
                "user_profile": {"identifier_kc_username": new_kc},
            }
        else:
            user_changes = {}

        stack.enter_context(
            patch(
                "invenio_remote_user_data_kcworks.services.service.CILogonHelpers."
                "calculate_user_changes",
                return_value=(user_changes, {}),
            )
        )
        stack.enter_context(
            patch(
                "invenio_remote_user_data_kcworks.services.service.CILogonHelpers."
                "update_local_user_data",
                return_value={"user": {}, "groups": []},
            )
        )
        return stack

    def test_dispatches_task_when_username_changes(self, app, user_factory, db):
        """Committed rename triggers `rewrite_records_for_kc_username_change.delay`."""
        from invenio_access.permissions import system_identity

        from invenio_remote_user_data_kcworks.proxies import (
            current_remote_user_data_service,
        )
        from invenio_remote_user_data_kcworks.types.profiles_api import APIResponse
        from tests.fixtures.idms import minimal_api_response, minimal_profile

        fixture = user_factory(
            email="dispatched@example.org",
            kc_username="oldname",
            oauth_src="cilogon",
            oauth_id="sub-d",
        )

        remote_in: APIResponse = minimal_api_response(
            "sub-d", profile=minimal_profile(username="newname")
        )

        with self._patch_helpers(old_kc="oldname", new_kc="newname"):
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
        """Email-only update: same kc_username → no task dispatched."""
        from invenio_access.permissions import system_identity

        from invenio_remote_user_data_kcworks.proxies import (
            current_remote_user_data_service,
        )
        from invenio_remote_user_data_kcworks.types.profiles_api import APIResponse
        from tests.fixtures.idms import minimal_api_response, minimal_profile

        fixture = user_factory(
            email="unchanged@example.org",
            kc_username="samename",
            oauth_src="cilogon",
            oauth_id="sub-u",
        )

        remote_in: APIResponse = minimal_api_response(
            "sub-u", profile=minimal_profile(username="samename")
        )

        with self._patch_helpers(old_kc="samename", new_kc="samename"):
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
