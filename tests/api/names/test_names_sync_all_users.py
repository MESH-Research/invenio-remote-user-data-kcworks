# Copyright (C) 2024-2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Tests for `NamesSyncService.sync_all_users_from_profiles`."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from invenio_remote_user_data_kcworks.config import NamesUserSyncClassification
from invenio_remote_user_data_kcworks.services.names_sync import NamesSyncService


@pytest.fixture()
def service(base_app) -> NamesSyncService:
    """A `NamesSyncService` bound to the pytest-invenio base app.

    Returns:
        A freshly constructed `NamesSyncService`.
    """
    return NamesSyncService(base_app)


def _user(
    user_id: int,
    *,
    kc_username: str | None = "kc-user",
) -> SimpleNamespace:
    """Build a minimal user object with an optional KC username profile field.

    Returns:
        A `User`-shaped namespace.
    """
    return SimpleNamespace(
        id=user_id,
        user_profile=(
            {"identifier_kc_username": kc_username}
            if kc_username is not None
            else {}
        ),
    )


def test_classify_user_for_names_sync_returns_enum_members(service):
    """Classification outcomes are stable `NamesUserSyncClassification` values."""
    with_kc = SimpleNamespace(
        id=1,
        user_profile={"identifier_kc_username": "alice"},
    )
    without_kc = SimpleNamespace(id=2, user_profile={})

    assert service.classify_user_for_names_sync(with_kc) == (
        NamesUserSyncClassification.ELIGIBLE
    )
    assert service.classify_user_for_names_sync(without_kc) == (
        NamesUserSyncClassification.NO_KC_USERNAME
    )

    with patch.object(service, "_read_existing", return_value=object()):
        assert service.classify_user_for_names_sync(
            with_kc, missing_only=True
        ) == NamesUserSyncClassification.HAS_NAMES

    with patch.object(service, "_read_existing", return_value=None):
        assert service.classify_user_for_names_sync(
            with_kc, missing_only=True
        ) == NamesUserSyncClassification.ELIGIBLE


def test_sync_all_users_calls_upsert_name_for_user(service):
    """Eligible users are upserted via `upsert_name_for_user`."""
    users = [
        _user(1, kc_username="alice"),
        _user(2, kc_username=None),
        _user(3, kc_username="carol"),
    ]

    with (
        patch.object(service, "_iter_local_users", return_value=iter(users)),
        patch.object(
            service,
            "upsert_name_for_user",
            side_effect=[{"id": "alice"}, None],
        ) as upsert,
    ):
        stats = service.sync_all_users_from_profiles()

    assert stats == {
        "users_scanned": 3,
        "eligible": 2,
        "upserted": 1,
        "no_data": 1,
        "skipped_no_kc_username": 1,
        "skipped_has_names": 0,
        "errors": 0,
    }
    assert [call.args[0].id for call in upsert.call_args_list] == [1, 3]


def test_sync_all_users_missing_only_skips_existing_names(service):
    """`missing_only` skips users who already have a Names PID."""
    users = [_user(10), _user(11)]

    with (
        patch.object(service, "_iter_local_users", return_value=iter(users)),
        patch.object(service, "_read_existing", side_effect=[MagicMock(), None]),
        patch.object(
            service, "upsert_name_for_user", return_value={"id": "user-11"}
        ) as upsert,
    ):
        stats = service.sync_all_users_from_profiles(missing_only=True)

    assert stats["eligible"] == 1
    assert stats["skipped_has_names"] == 1
    upsert.assert_called_once()
    assert upsert.call_args.args[0].id == 11


def test_sync_all_users_dry_run_does_not_upsert(service):
    """Dry-run counts eligibility without calling `upsert_name_for_user`."""
    users = [_user(5)]

    with (
        patch.object(service, "_iter_local_users", return_value=iter(users)),
        patch.object(service, "upsert_name_for_user") as upsert,
    ):
        stats = service.sync_all_users_from_profiles(dry_run=True)

    assert stats["eligible"] == 1
    assert stats["upserted"] == 0
    upsert.assert_not_called()


def test_sync_all_users_limit_caps_eligible_processing(service):
    """`limit` stops after the requested number of eligible users."""
    users = [_user(i, kc_username=f"user-{i}") for i in (1, 2, 3)]

    with (
        patch.object(service, "_iter_local_users", return_value=iter(users)),
        patch.object(
            service, "upsert_name_for_user", return_value={"id": "ok"}
        ) as upsert,
    ):
        stats = service.sync_all_users_from_profiles(limit=2)

    assert stats["users_scanned"] == 3
    assert stats["eligible"] == 2
    assert upsert.call_count == 2


def test_sync_all_users_counts_upsert_errors(service):
    """A failing upsert is logged and counted without aborting."""
    users = [_user(7)]

    with (
        patch.object(service, "_iter_local_users", return_value=iter(users)),
        patch.object(
            service, "upsert_name_for_user", side_effect=RuntimeError("boom")
        ),
    ):
        stats = service.sync_all_users_from_profiles()

    assert stats["errors"] == 1
    assert stats["upserted"] == 0
