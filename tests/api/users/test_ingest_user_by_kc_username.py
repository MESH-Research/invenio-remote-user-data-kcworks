# Copyright (C) 2024-2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Orchestration tests for `do_ingest_user_by_kc_username`.

The service and downstream tasks are mocked; only branch selection and call
wiring are asserted.

Sequence tested runs: skip existing → subs → created vs members → names sync.

See `tests/api/user_data/test_username_ingest_service.py` for the underlying
service helpers with real DB/search where users are created.
"""

from unittest.mock import MagicMock, patch

from invenio_remote_user_data_kcworks import tasks as tasks_mod
from invenio_remote_user_data_kcworks.tasks import do_ingest_user_by_kc_username
from tests.fixtures.idms import minimal_api_response


def test_skips_when_local_user_already_exists(base_app):
    """Existing local KC username is a no-op (returns None)."""
    fake_service = MagicMock()
    fake_service.find_local_user_by_kc_username.return_value = MagicMock(id=99)

    with (
        base_app.app_context(),
        patch.object(tasks_mod, "current_remote_user_data_service", fake_service),
    ):
        result = do_ingest_user_by_kc_username("alice")

    assert result is None
    fake_service.fetch_subs_profile_for_kc_username.assert_not_called()
    fake_service.provision_user_from_members_profile.assert_not_called()


def test_delegates_to_do_user_created_when_subs_payload_exists(base_app):
    """subs/{username}/ hit delegates to sub-first created path."""
    payload = minimal_api_response(
        "http://cilogon.org/serverE/users/alice-sub",
        username="alice",
    )
    fake_service = MagicMock()
    fake_service.find_local_user_by_kc_username.return_value = None
    fake_service.fetch_subs_profile_for_kc_username.return_value = payload
    fake_created = MagicMock(return_value=42)

    with (
        base_app.app_context(),
        patch.object(tasks_mod, "current_remote_user_data_service", fake_service),
        patch.object(tasks_mod, "do_user_created", fake_created),
    ):
        result = do_ingest_user_by_kc_username("alice", source="knowledgeCommons")

    assert result == 42
    fake_created.assert_called_once_with(
        "knowledgeCommons",
        "http://cilogon.org/serverE/users/alice-sub",
        remote_data=payload,
    )
    fake_service.provision_user_from_members_profile.assert_not_called()


def test_provisions_from_members_when_no_sub(base_app):
    """No subs payload falls through to members-only provision."""
    fake_user = MagicMock()
    fake_user.id = 77
    fake_service = MagicMock()
    fake_service.find_local_user_by_kc_username.return_value = None
    fake_service.fetch_subs_profile_for_kc_username.return_value = None
    fake_service.provision_user_from_members_profile.return_value = fake_user
    fake_sync = MagicMock()

    with (
        base_app.app_context(),
        patch.object(tasks_mod, "current_remote_user_data_service", fake_service),
        patch.object(tasks_mod, "sync_user_to_names", fake_sync),
    ):
        result = do_ingest_user_by_kc_username("bob")

    assert result == 77
    fake_service.provision_user_from_members_profile.assert_called_once()
    fake_sync.delay.assert_called_once_with(77)


def test_members_provision_miss_returns_none(base_app):
    """When members provision returns None, ingest row counts as skipped."""
    fake_service = MagicMock()
    fake_service.find_local_user_by_kc_username.return_value = None
    fake_service.fetch_subs_profile_for_kc_username.return_value = None
    fake_service.provision_user_from_members_profile.return_value = None

    with (
        base_app.app_context(),
        patch.object(tasks_mod, "current_remote_user_data_service", fake_service),
    ):
        result = do_ingest_user_by_kc_username("ghost")

    assert result is None
