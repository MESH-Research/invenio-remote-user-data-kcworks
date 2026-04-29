# Copyright (C) 2024-2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Unit tests for ``CitedNamesUpsertComponent``.

These tests exercise the component as a pure function of its inputs:

* the deposit ``data`` dict (creators / contributors with ORCID iDs),
* the (mocked) ``current_names_sync_service.upsert_cited_orcid_name``.

End-to-end integration with the live RDM record service is out of scope
here; that flow is exercised by the broader deposit-form tests once the
component is wired into ``RDM_RECORDS_SERVICE_COMPONENTS``.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask

from invenio_remote_user_data_kcworks.services.components import (
    cited_names_component as mod,
)
from invenio_remote_user_data_kcworks.services.components.cited_names_component import (
    CitedNamesUpsertComponent,
)
from invenio_remote_user_data_kcworks.utils.orcid_payload import (
    build_orcid_payload as _build_payload,
)
from invenio_remote_user_data_kcworks.utils.orcid_payload import (
    collect_orcid_payloads as _collect_orcid_payloads,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def app_ctx():
    """Push a minimal Flask app context for ``current_app.logger`` calls.

    Yields:
        The Flask app whose context is active for the test.
    """
    app = Flask("cited-names-tests")
    with app.app_context():
        yield app


@pytest.fixture
def upsert_mock():
    """Replace ``current_names_sync_service`` in the component's module with a mock.

    The real symbol is a ``LocalProxy`` that resolves to a Flask extension
    registered by ``invenio-remote-user-data-kcworks``; resolving it would
    require a fully-initialized Invenio app, which these unit tests
    deliberately avoid. Swapping the module attribute lets the component's
    ``current_names_sync_service.upsert_cited_orcid_name(...)`` call hit a
    plain mock instead.

    Yields:
        The ``MagicMock`` standing in for ``upsert_cited_orcid_name``.
    """
    fake_service = MagicMock(name="current_names_sync_service")
    fake_service.upsert_cited_orcid_name.return_value = {"id": "stub"}
    with patch.object(mod, "current_names_sync_service", new=fake_service):
        yield fake_service.upsert_cited_orcid_name


@pytest.fixture
def component():
    """Construct a ``CitedNamesUpsertComponent`` with a stand-in service.

    Returns:
        A bare ``CitedNamesUpsertComponent`` ready to receive lifecycle calls.
    """
    return CitedNamesUpsertComponent(service=None)


def _data(creators=None, contributors=None) -> dict[str, Any]:
    """Build a draft-shaped ``data`` dict from the given creator lists.

    Args:
        creators: Optional list of creator entries.
        contributors: Optional list of contributor entries.

    Returns:
        A dict with a ``metadata`` key holding ``creators`` and ``contributors``.
    """
    return {
        "metadata": {
            "creators": creators or [],
            "contributors": contributors or [],
        }
    }


def _personal(
    family: str,
    given: str = "",
    orcid: str | None = None,
    affiliations: list[dict] | None = None,
) -> dict[str, Any]:
    """Build a single personal ``creators[*]`` / ``contributors[*]`` entry.

    Args:
        family: Family name.
        given: Given name (optional).
        orcid: Optional ORCID identifier value.
        affiliations: Optional list of ``{"name": ...}`` affiliations.

    Returns:
        A creator/contributor entry dict suitable for the ``data`` payload.
    """
    person = {
        "type": "personal",
        "family_name": family,
        "given_name": given,
    }
    if orcid is not None:
        person["identifiers"] = [{"scheme": "orcid", "identifier": orcid}]
    return {"person_or_org": person, "affiliations": affiliations or []}


def _org(name: str, orcid: str | None = None) -> dict[str, Any]:
    """Build an organizational creator entry (which the component must ignore).

    Args:
        name: Organization name.
        orcid: Optional (and intentionally meaningless) ORCID identifier.

    Returns:
        A creator entry dict for an organizational contributor.
    """
    org = {"type": "organizational", "name": name}
    if orcid is not None:
        org["identifiers"] = [{"scheme": "orcid", "identifier": orcid}]
    return {"person_or_org": org}


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


class TestBuildPayload:
    """Assemble Names-record payload from ORCID + person_or_org + affiliations."""

    def test_full_payload_shape(self):
        """All fields populated when all inputs are present."""
        payload = _build_payload(
            "0000-0002-1825-0097",
            {"family_name": "Curie", "given_name": "Marie"},
            [{"name": "University of Paris"}, {"name": "Sorbonne"}],
        )
        assert payload == {
            "id": "0000-0002-1825-0097",
            "given_name": "Marie",
            "family_name": "Curie",
            "name": "Curie, Marie",
            "identifiers": [{"scheme": "orcid", "identifier": "0000-0002-1825-0097"}],
            "affiliations": [
                {"name": "University of Paris"},
                {"name": "Sorbonne"},
            ],
        }

    def test_prefers_existing_full_name_over_composed_form(self):
        """When ``person_or_org["name"]`` is set, it wins over ``family, given``."""
        payload = _build_payload(
            "0000-0002-1825-0097",
            {
                "family_name": "van der Berg",
                "given_name": "Jan",
                "name": "Jan van der Berg",
            },
            [],
        )
        assert payload["name"] == "Jan van der Berg"

    def test_missing_given_name_falls_back_to_family_only(self):
        """Display name is family-only when no given name is present."""
        payload = _build_payload(
            "0000-0002-1111-0000",
            {"family_name": "Plato"},
            [],
        )
        assert payload["name"] == "Plato"

    def test_missing_both_names_falls_back_to_orcid(self):
        """Display name falls back to the bare ORCID when no name is present."""
        payload = _build_payload(
            "0000-0002-1111-0000",
            {},
            [],
        )
        assert payload["name"] == "0000-0002-1111-0000"

    def test_blank_affiliation_names_filtered_out(self):
        """Affiliations with empty/missing names are dropped from the payload."""
        payload = _build_payload(
            "0000-0002-1111-0000",
            {"family_name": "Doe"},
            [{"name": ""}, {"name": "  "}, {"name": "MIT"}, {"id": "x"}],
        )
        assert payload["affiliations"] == [{"name": "MIT"}]


class TestCollectOrcidPayloads:
    """Walk creators+contributors; emit one payload per ORCID-bearing person."""

    def test_returns_empty_when_no_creators_or_contributors(self):
        """Empty / missing creators+contributors lists yield no payloads."""
        assert _collect_orcid_payloads({}) == []
        assert _collect_orcid_payloads({"creators": [], "contributors": []}) == []

    def test_skips_personal_entries_without_orcid(self):
        """Personal entries with no ORCID identifier yield no payload."""
        data = _data(creators=[_personal("Doe", "Jane")])
        assert _collect_orcid_payloads(data["metadata"]) == []

    def test_skips_organizational_entries_even_with_orcid(self):
        """Organizational entries are ignored even if they carry an ORCID."""
        data = _data(creators=[_org("ACME Corp", orcid="0000-0002-1825-0097")])
        assert _collect_orcid_payloads(data["metadata"]) == []

    def test_emits_one_payload_per_orcid_personal_entry(self):
        """Each personal entry with an ORCID across creators+contributors emits."""
        data = _data(
            creators=[
                _personal("Curie", "Marie", "0000-0002-1825-0097"),
                _personal("Doe", "Jane"),
            ],
            contributors=[
                _personal("Einstein", "Albert", "0000-0001-2345-6789"),
            ],
        )
        payloads = _collect_orcid_payloads(data["metadata"])
        assert [p["id"] for p in payloads] == [
            "0000-0002-1825-0097",
            "0000-0001-2345-6789",
        ]

    def test_dedupes_repeated_orcid_within_one_draft(self):
        """The same ORCID listed in both creators and contributors collapses to one."""
        data = _data(
            creators=[_personal("Curie", "Marie", "0000-0002-1825-0097")],
            contributors=[_personal("Curie", "M.", "0000-0002-1825-0097")],
        )
        payloads = _collect_orcid_payloads(data["metadata"])
        assert len(payloads) == 1
        assert payloads[0]["id"] == "0000-0002-1825-0097"


# ---------------------------------------------------------------------------
# Component lifecycle
# ---------------------------------------------------------------------------


class TestComponentCreate:
    """``create`` upserts each ORCID-bearing creator/contributor exactly once."""

    def test_no_data_is_a_no_op(self, app_ctx, component, upsert_mock):
        """A ``None`` ``data`` argument short-circuits before upsert calls."""
        component.create(identity=None, data=None)
        upsert_mock.assert_not_called()

    def test_no_orcid_creators_is_a_no_op(self, app_ctx, component, upsert_mock):
        """Drafts with creators but no ORCIDs trigger no upsert calls."""
        data = _data(creators=[_personal("Doe", "Jane")])
        component.create(identity=None, data=data)
        upsert_mock.assert_not_called()

    def test_calls_upsert_for_each_orcid_creator(self, app_ctx, component, upsert_mock):
        """Each unique ORCID across creators+contributors yields one upsert call."""
        data = _data(
            creators=[
                _personal(
                    "Curie",
                    "Marie",
                    "0000-0002-1825-0097",
                    [{"name": "Sorbonne"}],
                ),
                _personal("Doe", "Jane"),
            ],
            contributors=[
                _personal(
                    "Einstein",
                    "Albert",
                    "0000-0001-2345-6789",
                ),
            ],
        )
        component.create(identity=None, data=data)

        assert upsert_mock.call_count == 2
        called_ids = [call.args[0]["id"] for call in upsert_mock.call_args_list]
        assert called_ids == ["0000-0002-1825-0097", "0000-0001-2345-6789"]
        for call in upsert_mock.call_args_list:
            assert call.kwargs == {"source": "creatibutor"}


class TestComponentUpdateDraft:
    """``update_draft`` runs the same scan-and-upsert pipeline as ``create``."""

    def test_update_draft_dispatches_like_create(self, app_ctx, component, upsert_mock):
        """``update_draft`` triggers one upsert per ORCID-bearing person."""
        data = _data(creators=[_personal("Curie", "Marie", "0000-0002-1825-0097")])
        component.update_draft(identity=None, data=data)
        upsert_mock.assert_called_once()


class TestComponentErrorHandling:
    """Failures from ``upsert_cited_orcid_name`` are logged but never re-raised."""

    def test_exception_does_not_propagate(self, app_ctx, component, upsert_mock):
        """A raise from upsert is caught — the draft save flow is never broken."""
        upsert_mock.side_effect = RuntimeError("Names service exploded")
        data = _data(creators=[_personal("Curie", "Marie", "0000-0002-1825-0097")])
        component.update_draft(identity=None, data=data)

    def test_one_failure_does_not_block_other_orcids(
        self, app_ctx, component, upsert_mock
    ):
        """A failure on one ORCID does not stop the loop from processing the rest."""

        def _fail_first(payload, **kwargs):
            if payload["id"] == "0000-0002-1825-0097":
                raise RuntimeError("boom")
            return {"id": "ok"}

        upsert_mock.side_effect = _fail_first
        data = _data(
            creators=[
                _personal("Curie", "Marie", "0000-0002-1825-0097"),
                _personal("Einstein", "Albert", "0000-0001-2345-6789"),
            ]
        )
        component.update_draft(identity=None, data=data)
        assert upsert_mock.call_count == 2
