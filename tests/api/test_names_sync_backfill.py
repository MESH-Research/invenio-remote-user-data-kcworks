# Copyright (C) 2024-2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""End-to-end tests for ``NamesSyncService.backfill_cited_orcid_from_records``.

Each scenario builds a small synthetic published-RDM-records corpus (a list
of metadata-bearing dicts), mocks the live RDM record service's ``scan()``
to return that corpus, mocks ``upsert_cited_orcid_name`` so we can observe
the calls without touching the real Names service, and compares the
returned stats dict against an explicit expected dict.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from invenio_remote_user_data_kcworks.services import names_sync as ns_mod
from invenio_remote_user_data_kcworks.services.names_sync import NamesSyncService


@pytest.fixture()
def service(base_app) -> NamesSyncService:
    """A `NamesSyncService` bound to the pytest-invenio base app.

    Returns:
        A freshly constructed service whose `names_service` is never
        touched (we mock the only call site, `upsert_cited_orcid_name`).
    """
    return NamesSyncService(base_app)


def _personal(orcid: str | None, *, given="A.", family="Author") -> dict[str, Any]:
    """A personal-type creator/contributor entry with optional ORCID.

    Returns:
        A dict shaped like a creator/contributor entry.
    """
    person: dict[str, Any] = {
        "type": "personal",
        "name": f"{family}, {given}",
        "given_name": given,
        "family_name": family,
    }
    if orcid:
        person["identifiers"] = [{"scheme": "orcid", "identifier": orcid}]
    return {"person_or_org": person, "affiliations": []}


def _organizational(name: str, *, orcid: str | None = None) -> dict[str, Any]:
    """An organizational entry; ORCIDs here must be ignored by the collector.

    Returns:
        A dict shaped like an organizational creator/contributor entry.
    """
    person: dict[str, Any] = {"type": "organizational", "name": name}
    if orcid:
        person["identifiers"] = [{"scheme": "orcid", "identifier": orcid}]
    return {"person_or_org": person, "affiliations": []}


def _record(creators=None, contributors=None) -> dict[str, Any]:
    """A minimal hit-shaped dict matching the metadata layout `scan().hits` returns.

    Returns:
        A dict with a single ``metadata`` key holding the supplied
        creator / contributor lists.
    """
    return {
        "metadata": {
            "creators": creators or [],
            "contributors": contributors or [],
        }
    }


def _patched_scan(monkeypatch, hits: list[dict[str, Any]]) -> MagicMock:
    """Patch ``current_rdm_records_service.scan`` to return ``hits``.

    Replaces the symbol on the ``names_sync`` module (where it's bound by
    the top-level ``from invenio_rdm_records.proxies import ...``);
    patching the upstream proxies module would have no effect on the
    already-bound local name.

    Returns:
        The MagicMock standing in for the records service so each test
        can inspect ``scan(...)`` calls it received.
    """
    fake_scan_result = MagicMock()
    fake_scan_result.hits = iter(hits)

    fake_records_service = MagicMock()
    fake_records_service.scan.return_value = fake_scan_result

    monkeypatch.setattr(
        ns_mod, "current_rdm_records_service", fake_records_service
    )
    return fake_records_service


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------


def test_empty_corpus_returns_zeroed_stats(service, monkeypatch):
    """Walking an empty corpus does no upserts and returns all-zero stats."""
    _patched_scan(monkeypatch, [])
    upsert = MagicMock()

    with patch.object(service, "upsert_cited_orcid_name", upsert):
        stats = service.backfill_cited_orcid_from_records()

    assert stats == {
        "records_scanned": 0,
        "payloads_seen": 0,
        "upserted": 0,
        "errors": 0,
    }
    upsert.assert_not_called()


def test_mixed_corpus_upserts_only_personal_orcid_creators(service, monkeypatch):
    """Skips org entries and personal entries without ORCID; dedupes within record.

    Corpus: 3 records.
        R1 — 1 personal w/ ORCID, 1 organizational w/ ORCID-shaped id, 1 personal w/o id
        R2 — 1 personal w/ ORCID (different from R1)
        R3 — 1 personal w/ ORCID duplicated as creator AND contributor (one payload)
    """
    hits = [
        _record(
            creators=[
                _personal("0000-0001-1111-1111", given="Ada", family="Lovelace"),
                _organizational("ACME, Inc.", orcid="0000-0002-9999-9999"),
                _personal(None, given="Anon", family="Mouse"),
            ]
        ),
        _record(
            creators=[
                _personal("0000-0002-2222-2222", given="Boris", family="Karloff")
            ]
        ),
        _record(
            creators=[
                _personal("0000-0003-3333-3333", given="Curie", family="Marie")
            ],
            contributors=[
                _personal("0000-0003-3333-3333", given="Curie", family="Marie")
            ],
        ),
    ]
    _patched_scan(monkeypatch, hits)
    upsert = MagicMock()

    with patch.object(service, "upsert_cited_orcid_name", upsert):
        stats = service.backfill_cited_orcid_from_records()

    assert stats == {
        "records_scanned": 3,
        "payloads_seen": 3,
        "upserted": 3,
        "errors": 0,
    }
    seen_orcids = sorted(call.args[0]["id"] for call in upsert.call_args_list)
    assert seen_orcids == [
        "0000-0001-1111-1111",
        "0000-0002-2222-2222",
        "0000-0003-3333-3333",
    ]
    for call in upsert.call_args_list:
        assert call.kwargs.get("source") == "backfill"


def test_dry_run_counts_payloads_but_skips_upserts(service, monkeypatch):
    """`dry_run=True` reports what *would* be upserted without doing it."""
    hits = [
        _record(creators=[_personal("0000-0001-1111-1111")]),
        _record(creators=[_personal("0000-0002-2222-2222")]),
    ]
    _patched_scan(monkeypatch, hits)
    upsert = MagicMock()

    with patch.object(service, "upsert_cited_orcid_name", upsert):
        stats = service.backfill_cited_orcid_from_records(dry_run=True)

    assert stats == {
        "records_scanned": 2,
        "payloads_seen": 2,
        "upserted": 0,
        "errors": 0,
    }
    upsert.assert_not_called()


def test_limit_caps_records_scanned(service, monkeypatch):
    """`limit=N` stops after N records, even if more are available."""
    hits = [
        _record(creators=[_personal(f"0000-0001-0000-{i:04d}")]) for i in range(5)
    ]
    _patched_scan(monkeypatch, hits)
    upsert = MagicMock()

    with patch.object(service, "upsert_cited_orcid_name", upsert):
        stats = service.backfill_cited_orcid_from_records(limit=2)

    assert stats == {
        "records_scanned": 2,
        "payloads_seen": 2,
        "upserted": 2,
        "errors": 0,
    }
    assert upsert.call_count == 2


def test_upsert_failures_are_counted_not_raised(service, monkeypatch):
    """A raising upsert increments `errors`; the walk continues."""
    hits = [
        _record(creators=[_personal("0000-0001-1111-1111")]),
        _record(creators=[_personal("0000-0002-2222-2222")]),
        _record(creators=[_personal("0000-0003-3333-3333")]),
    ]
    _patched_scan(monkeypatch, hits)

    def upsert_side_effect(payload, **_kwargs):
        if payload["id"] == "0000-0002-2222-2222":
            raise RuntimeError("simulated names-service failure")
        return {"id": payload["id"]}

    upsert = MagicMock(side_effect=upsert_side_effect)

    with patch.object(service, "upsert_cited_orcid_name", upsert):
        stats = service.backfill_cited_orcid_from_records()

    assert stats == {
        "records_scanned": 3,
        "payloads_seen": 3,
        "upserted": 2,
        "errors": 1,
    }
    assert upsert.call_count == 3
