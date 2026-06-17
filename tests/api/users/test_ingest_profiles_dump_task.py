# Copyright (C) 2024-2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Wiring tests for the `do_ingest_profiles_dump` Celery task.

Exercises file parsing, format sniffing, stats, and per-row delegation with
`do_user_created` / `do_ingest_user_by_kc_username` mocked (no real users).
"""

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from invenio_remote_user_data_kcworks import tasks as tasks_mod
from invenio_remote_user_data_kcworks.tasks import do_ingest_profiles_dump


def _profiles_row(sub: str, *, email: str = "x@example.org") -> dict[str, Any]:
    """A minimum-valid Profiles APIResponse-shaped dict for one user.

    Returns:
        A JSON-serializable dict suitable to feed to
        `APIResponse.model_validate`.
    """
    return {
        "data": [
            {
                "sub": sub,
                "profile": {
                    "username": sub,
                    "email": email,
                    "name": "Test User",
                    "first_name": "Test",
                    "last_name": "User",
                    "institutional_affiliation": "ACME",
                    "groups": [],
                    "orcid": "",
                },
            }
        ],
        "meta": {"authorized": True},
        "next": None,
        "previous": None,
    }


# ---------------------------------------------------------------------------
# JSONL path
# ---------------------------------------------------------------------------


def test_jsonl_with_auto_sniff_replays_each_row_with_remote_data(base_app, tmp_path):
    """Each JSONL line becomes a `do_user_created(..., remote_data=...)` call.

    The task should sniff format = jsonl from the leading `{`, validate
    each row through `APIResponse`, extract `data[0].sub` as the
    oauth_id, and pass the parsed payload as `remote_data` so no live
    Profiles API I/O is performed.
    """
    p = tmp_path / "dump.jsonl"
    rows = [_profiles_row("sub-aaa"), _profiles_row("sub-bbb")]
    p.write_text("\n".join(json.dumps(r) for r in rows))

    fake = MagicMock(side_effect=[101, 202])
    with base_app.app_context(), patch.object(tasks_mod, "do_user_created", fake):
        stats = do_ingest_profiles_dump(str(p))

    assert stats == {
        "rows_seen": 2,
        "processed": 2,
        "skipped": 0,
        "errors": 0,
    }
    assert fake.call_count == 2
    seen_subs = [c.args[1] for c in fake.call_args_list]
    assert seen_subs == ["sub-aaa", "sub-bbb"]
    for call in fake.call_args_list:
        # remote_data must be present and be the parsed APIResponse.
        rd = call.kwargs["remote_data"]
        assert rd.data[0].sub == call.args[1]


def test_jsonl_skips_blank_lines(base_app, tmp_path):
    """Blank lines in the JSONL file are not counted and not processed."""
    p = tmp_path / "dump.jsonl"
    rows = [_profiles_row("sub-aaa"), _profiles_row("sub-bbb")]
    p.write_text(
        "\n".join(json.dumps(r) for r in rows[:1])
        + "\n\n\n"
        + "\n".join(json.dumps(r) for r in rows[1:])
        + "\n"
    )

    fake = MagicMock(return_value=1)
    with base_app.app_context(), patch.object(tasks_mod, "do_user_created", fake):
        stats = do_ingest_profiles_dump(str(p), fmt="jsonl")

    assert stats["rows_seen"] == 2
    assert fake.call_count == 2


def test_jsonl_row_with_empty_data_is_skipped(base_app, tmp_path):
    """Rows whose `data` array is empty are counted as `skipped`, not `errors`."""
    p = tmp_path / "dump.jsonl"
    p.write_text(
        json.dumps({"data": [], "meta": {"authorized": True},
                    "next": None, "previous": None})
        + "\n"
        + json.dumps(_profiles_row("sub-aaa"))
        + "\n"
    )

    fake = MagicMock(return_value=42)
    with base_app.app_context(), patch.object(tasks_mod, "do_user_created", fake):
        stats = do_ingest_profiles_dump(str(p), fmt="jsonl")

    assert stats == {
        "rows_seen": 2,
        "processed": 1,
        "skipped": 1,
        "errors": 0,
    }
    assert fake.call_count == 1


# ---------------------------------------------------------------------------
# Usernames path
# ---------------------------------------------------------------------------


def test_usernames_dump_delegates_parsed_lines_to_ingest_helper(base_app, tmp_path):
    """Exercise `do_ingest_profiles_dump` file-loop wiring for username CSV input.

    This is **not** an end-to-end username ingest test: `do_ingest_user_by_kc_username`
    is mocked, so no Profiles API calls or user provisioning occur.

    Asserts that the dump task:

    - auto-sniffs `usernames` format (header line is not JSON);
    - skips `#` comment lines, blank lines, and a `username` CSV header;
    - invokes `do_ingest_user_by_kc_username` once per remaining row with
      `source="knowledgeCommons"`;
    - maps non-`None` mock return values into `processed` stats.
    """
    p = tmp_path / "users.csv"
    p.write_text(
        "username\n"
        "# this is a comment\n"
        "alice\n"
        "\n"
        "bob\n"
        "carol\n"
    )

    fake = MagicMock(side_effect=[1, 2, 3])
    with (
        base_app.app_context(),
        patch.object(tasks_mod, "do_ingest_user_by_kc_username", fake),
    ):
        stats = do_ingest_profiles_dump(str(p))

    assert stats == {
        "rows_seen": 3,
        "processed": 3,
        "skipped": 0,
        "errors": 0,
    }
    seen = [c.args[0] for c in fake.call_args_list]
    assert seen == ["alice", "bob", "carol"]
    for call in fake.call_args_list:
        assert call.kwargs.get("source") == "knowledgeCommons"


def test_usernames_handles_extra_csv_columns(base_app, tmp_path):
    """If somebody hands us a wider CSV, only the first column is taken."""
    p = tmp_path / "users.csv"
    p.write_text("alice,foo\nbob,bar\n")

    fake = MagicMock(return_value=1)
    with (
        base_app.app_context(),
        patch.object(tasks_mod, "do_ingest_user_by_kc_username", fake),
    ):
        stats = do_ingest_profiles_dump(str(p), fmt="usernames")

    assert stats["rows_seen"] == 2
    assert [c.args[0] for c in fake.call_args_list] == ["alice", "bob"]


# ---------------------------------------------------------------------------
# Error tolerance & misc
# ---------------------------------------------------------------------------


def test_per_row_failures_are_counted_not_raised(base_app, tmp_path):
    """A raising row increments `errors`; the rest of the dump still runs."""
    p = tmp_path / "users.csv"
    p.write_text("alice\nbob\ncarol\n")

    def side_effect(username, **_kwargs):
        if username == "bob":
            raise RuntimeError("boom")
        return 99

    fake = MagicMock(side_effect=side_effect)
    with (
        base_app.app_context(),
        patch.object(tasks_mod, "do_ingest_user_by_kc_username", fake),
    ):
        stats = do_ingest_profiles_dump(str(p))

    assert stats == {
        "rows_seen": 3,
        "processed": 2,
        "skipped": 0,
        "errors": 1,
    }
    assert fake.call_count == 3


def test_do_user_created_returning_none_is_counted_as_skipped(base_app, tmp_path):
    """Rows where the underlying task returns `None` are `skipped`, not `errors`."""
    p = tmp_path / "users.csv"
    p.write_text("alice\nbob\n")

    fake = MagicMock(side_effect=[None, 99])
    with (
        base_app.app_context(),
        patch.object(tasks_mod, "do_ingest_user_by_kc_username", fake),
    ):
        stats = do_ingest_profiles_dump(str(p))

    assert stats == {
        "rows_seen": 2,
        "processed": 1,
        "skipped": 1,
        "errors": 0,
    }


def test_invalid_fmt_raises_value_error(base_app, tmp_path):
    """An unknown explicit `fmt` is rejected loudly before reading the file."""
    p = tmp_path / "users.csv"
    p.write_text("alice\n")

    with base_app.app_context(), pytest.raises(ValueError, match="unknown fmt"):
        do_ingest_profiles_dump(str(p), fmt="xml")


def test_empty_file_yields_zeroed_stats(base_app, tmp_path):
    """A whitespace-only file walks zero rows and makes zero calls."""
    p = tmp_path / "empty.csv"
    p.write_text("\n\n\n")

    fake = MagicMock()
    with base_app.app_context(), patch.object(tasks_mod, "do_user_created", fake):
        stats = do_ingest_profiles_dump(str(p))

    assert stats == {
        "rows_seen": 0,
        "processed": 0,
        "skipped": 0,
        "errors": 0,
    }
    fake.assert_not_called()
