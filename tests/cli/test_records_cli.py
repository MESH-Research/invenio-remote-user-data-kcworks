# Copyright (C) 2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Tests for `user-data records` CLI commands."""

from unittest.mock import MagicMock, patch

from invenio_remote_user_data_kcworks.cli import records as records_cli_mod
from invenio_remote_user_data_kcworks.cli.main import cli


def test_update_contributors_username_rejects_identical_usernames(cli_runner):
    """Old and new KC usernames must differ."""
    result = cli_runner(
        cli,
        "records",
        "update_contributors_username",
        "-o",
        "same",
        "-n",
        "same",
    )
    assert result.exit_code != 0
    assert "must differ" in result.output


def test_update_contributors_username_inline_calls_task(cli_runner):
    """Without --background, the shared task runs with prune_names=False."""
    fake_task = MagicMock(
        return_value={
            "records": {
                "published": {"matched": 1, "updated": 1, "failed": 0},
                "drafts": {"matched": 0, "updated": 0, "failed": 0},
            },
            "errors": 0,
        }
    )

    with patch.object(
        records_cli_mod,
        "rewrite_records_for_kc_username_change",
        fake_task,
    ):
        result = cli_runner(
            cli,
            "records",
            "update_contributors_username",
            "-o",
            "oldname",
            "-n",
            "newname",
        )

    assert result.exit_code == 0, result.output
    fake_task.assert_called_once_with(0, "oldname", "newname", prune_names=False)
    assert fake_task.delay.call_count == 0
    assert "published: matched=1 updated=1 failed=0" in result.output


def test_update_contributors_username_background_queues_task(cli_runner):
    """With --background, the CLI enqueues Celery with prune_names=False."""
    fake_async = MagicMock()
    fake_async.id = "task-abc"
    fake_task = MagicMock()
    fake_task.delay.return_value = fake_async

    with patch.object(
        records_cli_mod,
        "rewrite_records_for_kc_username_change",
        fake_task,
    ):
        result = cli_runner(
            cli,
            "records",
            "update_contributors_username",
            "--background",
            "-o",
            "oldname",
            "-n",
            "newname",
        )

    assert result.exit_code == 0, result.output
    fake_task.delay.assert_called_once_with(
        0, "oldname", "newname", prune_names=False
    )
    assert "Queued rewrite task: task-abc" in result.output


def test_update_contributors_username_dry_run_lists_records(cli_runner):
    """--dry-run scans and lists record IDs without calling the rewrite task."""
    fake_service = MagicMock()
    fake_service.find_record_ids_for_kc_username.return_value = {
        "published": ["pub-1", "pub-2"],
        "drafts": ["draft-1"],
    }
    fake_task = MagicMock()

    with (
        patch.object(
            records_cli_mod,
            "current_record_creatibutor_sync_service",
            fake_service,
        ),
        patch.object(
            records_cli_mod,
            "rewrite_records_for_kc_username_change",
            fake_task,
        ),
    ):
        result = cli_runner(
            cli,
            "records",
            "update_contributors_username",
            "--dry-run",
            "-o",
            "oldname",
            "-n",
            "newname",
        )

    assert result.exit_code == 0, result.output
    fake_service.find_record_ids_for_kc_username.assert_called_once_with("oldname")
    fake_task.assert_not_called()
    assert "published (2 record(s)):" in result.output
    assert "  pub-1" in result.output
    assert "  pub-2" in result.output
    assert "drafts (1 record(s)):" in result.output
    assert "  draft-1" in result.output
    assert "Total: 3 record(s) would be updated." in result.output


def test_update_contributors_username_rejects_dry_run_with_background(cli_runner):
    """--dry-run and --background are mutually exclusive."""
    result = cli_runner(
        cli,
        "records",
        "update_contributors_username",
        "--dry-run",
        "--background",
        "-o",
        "oldname",
        "-n",
        "newname",
    )
    assert result.exit_code != 0
    assert "cannot be used with --background" in result.output


def test_backfill_creatibutor_names_calls_service(cli_runner):
    """backfill-creatibutor-names forwards flags to the sync service."""
    fake_service = MagicMock()
    fake_service.backfill_creatibutor_display_names.return_value = {
        "users_scanned": 2,
        "users_eligible": 1,
        "records_updated": 3,
        "records_unchanged": 0,
        "records_failed": 0,
        "errors": 0,
    }

    with patch.object(
        records_cli_mod,
        "current_record_creatibutor_sync_service",
        fake_service,
    ):
        result = cli_runner(
            cli,
            "records",
            "backfill-creatibutor-names",
            "--dry-run",
            "--limit",
            "5",
            "--user-id",
            "42",
        )

    assert result.exit_code == 0, result.output
    fake_service.backfill_creatibutor_display_names.assert_called_once_with(
        dry_run=True,
        limit=5,
        user_id="42",
    )
    assert "records_updated=3" in result.output
