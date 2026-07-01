# Copyright (C) 2024-2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""End-to-end tests for the new `user-data` CLI subcommands.

The CLI is exercised through Click's `CliRunner` against the
top-level `cli` group. Underlying Celery tasks and service methods are
patched at the module boundary the CLI imports them from
(`invenio_remote_user_data_kcworks.cli`) so each test only verifies
*the CLI's* contract: argument plumbing, `--background` branching, and
output formatting.

User-resolution helpers reach through to `UserIdentity` queries; rather
than spinning up the full Invenio user stack, those tests patch
`_resolve_user_id_from_arg` (from `...cli`) directly.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from invenio_remote_user_data_kcworks.cli import names as names_cli_mod
from invenio_remote_user_data_kcworks.cli import users as users_cli_mod
from invenio_remote_user_data_kcworks.cli.main import cli


@pytest.fixture()
def runner(base_app):
    """A Flask CLI runner bound to the pytest-invenio `base_app`.

    Flask's `test_cli_runner()` (a thin subclass of Click's
    `CliRunner`) sets up the ambient app context that the
    `@with_appcontext`-decorated commands need.

    Returns:
        A `flask.testing.FlaskCliRunner` instance.
    """
    return base_app.test_cli_runner()


# ---------------------------------------------------------------------------
# `user-data names sync-now`
# ---------------------------------------------------------------------------


def test_sync_now_requires_at_least_one_id(runner):
    """Calling `sync-now` with no arguments fails fast with a usage error."""
    result = runner.invoke(cli, ["names", "sync-now"])
    assert result.exit_code != 0
    assert "Provide at least one user id" in result.output


def test_sync_now_inline_resolves_each_arg_and_calls_task(runner):
    """Each positional id is resolved and synced inline (no Celery delay)."""
    fake_resolve = MagicMock(side_effect=[101, 202])
    fake_sync = MagicMock(side_effect=[True, False])

    with (
        patch.object(names_cli_mod, "_resolve_user_id_from_arg", fake_resolve),
        patch.object(names_cli_mod, "sync_user_to_names", fake_sync),
    ):
        result = runner.invoke(cli, ["names", "sync-now", "11", "22"])

    assert result.exit_code == 0, result.output
    assert "11 -> user_id=101: ok" in result.output
    assert "22 -> user_id=202: no data" in result.output
    assert fake_sync.call_args_list == [((101,),), ((202,),)]
    assert fake_sync.delay.call_count == 0


def test_sync_now_unresolved_arg_is_skipped_not_raised(runner):
    """An id that doesn't resolve to a local user is reported and skipped."""
    fake_sync = MagicMock(return_value=True)

    with (
        patch.object(names_cli_mod, "_resolve_user_id_from_arg", return_value=None),
        patch.object(names_cli_mod, "sync_user_to_names", fake_sync),
    ):
        result = runner.invoke(cli, ["names", "sync-now", "ghost"])

    assert result.exit_code == 0, result.output
    assert "ghost: no matching user; skipped" in result.output
    fake_sync.assert_not_called()


def test_sync_now_background_dispatches_celery_task(runner):
    """`--background` calls `sync_user_to_names.delay` and prints the task id."""
    fake_sync = MagicMock()
    fake_sync.delay.return_value = MagicMock(id="task-aaa")

    with (
        patch.object(names_cli_mod, "_resolve_user_id_from_arg", return_value=42),
        patch.object(names_cli_mod, "sync_user_to_names", fake_sync),
    ):
        result = runner.invoke(cli, ["names", "sync-now", "--background", "irrelevant"])

    assert result.exit_code == 0, result.output
    assert "task-aaa" in result.output
    fake_sync.delay.assert_called_once_with(42)


# ---------------------------------------------------------------------------
# `user-data names backfill-cited-from-records`
# ---------------------------------------------------------------------------


def test_backfill_inline_calls_task_synchronously(runner):
    """Without `--background` the task runs inline; stats are echoed."""
    fake_task = MagicMock(
        return_value={
            "records_scanned": 10,
            "payloads_seen": 7,
            "upserted": 7,
            "errors": 0,
        }
    )
    with patch.object(names_cli_mod, "do_backfill_cited_from_records", fake_task):
        result = runner.invoke(
            cli,
            ["names", "backfill-cited-from-records", "--limit", "10"],
        )

    assert result.exit_code == 0, result.output
    fake_task.assert_called_once_with(limit=10, dry_run=False)
    assert fake_task.delay.call_count == 0
    assert "records_scanned=10" in result.output
    assert "upserted=7" in result.output


def test_backfill_dry_run_flag_is_forwarded(runner):
    """`--dry-run` propagates to the task call."""
    fake_task = MagicMock(
        return_value={
            "records_scanned": 5,
            "payloads_seen": 5,
            "upserted": 0,
            "errors": 0,
        }
    )
    with patch.object(names_cli_mod, "do_backfill_cited_from_records", fake_task):
        result = runner.invoke(
            cli, ["names", "backfill-cited-from-records", "--dry-run"]
        )

    assert result.exit_code == 0, result.output
    fake_task.assert_called_once_with(limit=None, dry_run=True)
    assert "upserted=0" in result.output


def test_backfill_background_dispatches_celery_task(runner):
    """`--background` queues the Celery task; the call is by-keyword."""
    fake_task = MagicMock()
    fake_task.delay.return_value = MagicMock(id="task-bbb")

    with patch.object(names_cli_mod, "do_backfill_cited_from_records", fake_task):
        result = runner.invoke(
            cli,
            [
                "names",
                "backfill-cited-from-records",
                "--background",
                "--limit",
                "100",
            ],
        )

    assert result.exit_code == 0, result.output
    assert "task-bbb" in result.output
    fake_task.delay.assert_called_once_with(limit=100, dry_run=False)
    fake_task.assert_not_called()


# ---------------------------------------------------------------------------
# `user-data users ingest-profiles-dump`
# ---------------------------------------------------------------------------


def test_ingest_inline_runs_task_synchronously(runner, tmp_path):
    """Without `--background` the task runs inline; stats are echoed."""
    p = tmp_path / "users.csv"
    p.write_text("alice\n")

    fake_task = MagicMock(
        return_value={"rows_seen": 1, "processed": 1, "skipped": 0, "errors": 0}
    )
    with patch.object(users_cli_mod, "do_ingest_profiles_dump", fake_task):
        result = runner.invoke(cli, ["users", "ingest-profiles-dump", str(p)])

    assert result.exit_code == 0, result.output
    fake_task.assert_called_once_with(
        str(p),
        fmt="auto",
        source="knowledgeCommons",
        limit=None,
        offset=1,
        rate_per_second=2.0,
    )
    assert "rows_seen=1" in result.output


def test_ingest_background_dispatches_celery_task(runner, tmp_path):
    """`--background` queues the Celery task with explicit format/source."""
    p = tmp_path / "dump.jsonl"
    p.write_text('{"data":[],"meta":{"authorized":true},"next":null,"previous":null}\n')

    fake_task = MagicMock()
    fake_task.delay.return_value = MagicMock(id="task-ccc")

    with patch.object(users_cli_mod, "do_ingest_profiles_dump", fake_task):
        result = runner.invoke(
            cli,
            [
                "users",
                "ingest-profiles-dump",
                "--background",
                "--format",
                "jsonl",
                "--source",
                "knowledgeCommons",
                str(p),
            ],
        )

    assert result.exit_code == 0, result.output
    assert "task-ccc" in result.output
    fake_task.delay.assert_called_once_with(
        str(p),
        fmt="jsonl",
        source="knowledgeCommons",
        offset=1,
        limit=None,
        rate_per_second=2.0,
    )
    fake_task.assert_not_called()


def test_ingest_limit_and_rate_per_second_forwarded_inline(runner, tmp_path):
    """`--limit` and `--rate-per-second` propagate to the synchronous task call."""
    p = tmp_path / "users.csv"
    p.write_text("alice\n")

    fake_task = MagicMock(
        return_value={"rows_seen": 1, "processed": 1, "skipped": 0, "errors": 0}
    )
    with patch.object(users_cli_mod, "do_ingest_profiles_dump", fake_task):
        result = runner.invoke(
            cli,
            [
                "users",
                "ingest-profiles-dump",
                "--limit",
                "25",
                "--rate-per-second",
                "0.5",
                str(p),
            ],
        )

    assert result.exit_code == 0, result.output
    fake_task.assert_called_once_with(
        str(p),
        fmt="auto",
        source="knowledgeCommons",
        limit=25,
        offset=1,
        rate_per_second=0.5,
    )


def test_ingest_limit_and_rate_per_second_forwarded_background(runner, tmp_path):
    """`--limit` and `--rate-per-second` propagate to the Celery `.delay()` call."""
    p = tmp_path / "users.csv"
    p.write_text("alice\n")

    fake_task = MagicMock()
    fake_task.delay.return_value = MagicMock(id="task-ddd")

    with patch.object(users_cli_mod, "do_ingest_profiles_dump", fake_task):
        result = runner.invoke(
            cli,
            [
                "users",
                "ingest-profiles-dump",
                "--background",
                "--limit",
                "10",
                "--rate-per-second",
                "0",
                str(p),
            ],
        )

    assert result.exit_code == 0, result.output
    assert "task-ddd" in result.output
    fake_task.delay.assert_called_once_with(
        str(p),
        fmt="auto",
        source="knowledgeCommons",
        limit=10,
        offset=1,
        rate_per_second=0.0,
    )
    fake_task.assert_not_called()


def test_ingest_rejects_missing_file(runner):
    """Click's `Path(exists=True)` validator surfaces a clean error."""
    result = runner.invoke(cli, ["users", "ingest-profiles-dump", "/no/such/file"])
    assert result.exit_code != 0
    assert "does not exist" in result.output.lower()


# ---------------------------------------------------------------------------
# `user-data names show`
# ---------------------------------------------------------------------------


def test_show_prints_record_when_pid_resolves(runner):
    """A successful direct read prints the record and never calls resolve()."""
    fake_names_service = MagicMock()
    fake_item = MagicMock()
    fake_item.to_dict.return_value = {"id": "abc", "name": "Test"}
    fake_names_service.read.return_value = fake_item

    fake_proxy = MagicMock()
    fake_proxy.names_service = fake_names_service

    with patch.object(names_cli_mod, "names_sync_service", fake_proxy):
        result = runner.invoke(cli, ["names", "show", "abc"])

    assert result.exit_code == 0, result.output
    assert "'id': 'abc'" in result.output
    fake_names_service.read.assert_called_once()
    fake_names_service.resolve.assert_not_called()


def test_show_falls_back_to_orcid_resolve_when_read_misses(runner):
    """A PID miss falls back to ORCID-scheme resolution; multiple hits print all."""
    from invenio_pidstore.errors import PIDDoesNotExistError

    fake_names_service = MagicMock()
    fake_names_service.read.side_effect = PIDDoesNotExistError(
        pid_type="names", pid_value="0000-0001-2345-6789"
    )
    fake_resolved = MagicMock()
    fake_resolved.to_dict.return_value = {
        "hits": {
            "hits": [
                {"id": "user-1", "name": "User One", "tags": ["kcworks-user"]},
                {
                    "id": "0000-0001-2345-6789",
                    "name": "Cited One",
                    "tags": ["kcworks-cited"],
                },
            ]
        }
    }
    fake_names_service.resolve.return_value = fake_resolved

    fake_proxy = MagicMock()
    fake_proxy.names_service = fake_names_service

    with patch.object(names_cli_mod, "names_sync_service", fake_proxy):
        result = runner.invoke(cli, ["names", "show", "0000-0001-2345-6789"])

    assert result.exit_code == 0, result.output
    assert "Found 2 record(s)" in result.output
    assert "user-1" in result.output
    assert "0000-0001-2345-6789" in result.output


def test_show_raises_clickexception_when_nothing_found(runner):
    """Both lookup paths missing yields a non-zero exit code with a clean message."""
    from invenio_pidstore.errors import PIDDoesNotExistError

    fake_names_service = MagicMock()
    fake_names_service.read.side_effect = PIDDoesNotExistError(
        pid_type="names", pid_value="ghost"
    )
    fake_names_service.resolve.side_effect = PIDDoesNotExistError(
        pid_type="orcid", pid_value="ghost"
    )

    fake_proxy = MagicMock()
    fake_proxy.names_service = fake_names_service

    with patch.object(names_cli_mod, "names_sync_service", fake_proxy):
        result = runner.invoke(cli, ["names", "show", "ghost"])

    assert result.exit_code != 0
    assert "ghost" in result.output
    assert "No Names record" in result.output


# ---------------------------------------------------------------------------
# `user-data names list-duplicates`
# ---------------------------------------------------------------------------


def test_list_duplicates_empty_emits_friendly_message(runner):
    """An empty result list prints the friendly empty-state line and exits 0."""
    fake_proxy = MagicMock()
    fake_proxy.list_duplicate_pairs.return_value = []

    with patch.object(names_cli_mod, "names_sync_service", fake_proxy):
        result = runner.invoke(cli, ["names", "list-duplicates"])

    assert result.exit_code == 0, result.output
    assert "No marked duplicate pairs." in result.output
    fake_proxy.list_duplicate_pairs.assert_called_once()
    # No dismiss-duplicate hint when there's nothing to dismiss.
    assert "dismiss-duplicate" not in result.output


def test_list_duplicates_prints_one_line_per_pair(runner):
    """A non-empty result prints the count, one line per pair, and the dismiss hint."""
    fake_proxy = MagicMock()
    fake_proxy.list_duplicate_pairs.return_value = [
        {
            "score": 0.95,
            "score_method": "family_exact+given_fuzzy",
            "a_uuid": "uuid-a",
            "a_pid": "kc|jdoe",
            "a_name": "Doe, John",
            "b_uuid": "uuid-b",
            "b_pid": "0000-0001-x",
            "b_name": "Doe, Jonathan",
        },
        {
            "score": 0.80,
            "score_method": "family_phonetic+given_fuzzy",
            "a_uuid": "uuid-c",
            "a_pid": "kc|mlin",
            "a_name": "Lin, Mei",
            "b_uuid": "uuid-d",
            "b_pid": "kc|mlin2",
            "b_name": "Lin, May",
        },
    ]

    with patch.object(names_cli_mod, "names_sync_service", fake_proxy):
        result = runner.invoke(cli, ["names", "list-duplicates"])

    assert result.exit_code == 0, result.output
    assert "2 marked duplicate pair(s):" in result.output
    assert (
        "score=0.95 method=family_exact+given_fuzzy  "
        'kc|jdoe (uuid-a) "Doe, John"  <->  '
        '0000-0001-x (uuid-b) "Doe, Jonathan"'
    ) in result.output
    assert (
        "score=0.8 method=family_phonetic+given_fuzzy  "
        'kc|mlin (uuid-c) "Lin, Mei"  <->  '
        'kc|mlin2 (uuid-d) "Lin, May"'
    ) in result.output
    assert "dismiss-duplicate" in result.output
    fake_proxy.list_duplicate_pairs.assert_called_once()
