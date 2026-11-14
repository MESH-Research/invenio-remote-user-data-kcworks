# Copyright (C) 2024-2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Unit tests for `CitedNamesUpsertComponent`.

These tests exercise the component as a pure function of its inputs:

* the deposit `data` dict (creators / contributors with ORCID iDs),
* the unit-of-work `TaskOp` registrations for post-commit Celery work.

End-to-end integration with the live RDM record service is out of scope
here; that flow is exercised by the broader deposit-form tests once the
component is wired into `RDM_RECORDS_SERVICE_COMPONENTS`.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from flask import Flask
from invenio_records_resources.services.uow import TaskOp

from invenio_remote_user_data_kcworks.config import KCNamesTag
from invenio_remote_user_data_kcworks.services.components.cited_names_component import (
    CitedNamesUpsertComponent,
)
from invenio_remote_user_data_kcworks.tasks import upsert_cited_orcid_name_task
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
    """Push a minimal Flask app context for `current_app.logger` calls.

    Yields:
        The Flask app whose context is active for the test.
    """
    app = Flask("cited-names-tests")
    with app.app_context():
        yield app


@pytest.fixture
def component():
    """Construct a `CitedNamesUpsertComponent` with a mock unit of work.

    Returns:
        A `CitedNamesUpsertComponent` whose `uow.register` is a `MagicMock`.
    """
    comp = CitedNamesUpsertComponent(service=None)
    comp.uow = MagicMock(name="uow")
    return comp


def _registered_task_ops(component: CitedNamesUpsertComponent) -> list[TaskOp]:
    """Return `TaskOp` instances passed to `component.uow.register`.

    Args:
        component: Component whose mock UoW was used under test.

    Returns:
        The registered `TaskOp` objects, in order.
    """
    return [
        call.args[0]
        for call in component.uow.register.call_args_list
        if call.args and isinstance(call.args[0], TaskOp)
    ]


def _data(creators=None, contributors=None) -> dict[str, Any]:
    """Build a draft-shaped `data` dict from the given creator lists.

    Args:
        creators: Optional list of creator entries.
        contributors: Optional list of contributor entries.

    Returns:
        A dict with a `metadata` key holding `creators` and `contributors`.
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
    """Build a single personal `creators[*]` / `contributors[*]` entry.

    Args:
        family: Family name.
        given: Given name (optional).
        orcid: Optional ORCID identifier value.
        affiliations: Optional list of `{"name": ...}` affiliations.

    Returns:
        A creator/contributor entry dict suitable for the `data` payload.
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
            "internal_id": None,
            "tags": [KCNamesTag.CITED],
            "given_name": "Marie",
            "family_name": "Curie",
            "name": "Curie, Marie",
            "identifiers": [{"scheme": "orcid", "identifier": "0000-0002-1825-0097"}],
            "affiliations": [
                {"name": "University of Paris"},
                {"name": "Sorbonne"},
            ],
            "props": {
                "display_name": "Curie, Marie",
                "name_parts": {"first": "Marie", "last": "Curie"},
                "family_token": "curie",
                "family_part_tokens": ["curie"],
                "family_phonetic_tokens": ["KR"],
            },
        }

    def test_prefers_existing_full_name_over_composed_form(self):
        """When `person_or_org["name"]` is set, it wins over `family, given`."""
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
        assert payload["props"]["display_name"] == "Jan van der Berg"
        assert payload["tags"] == [KCNamesTag.CITED]
        assert payload["props"]["family_part_tokens"] == [
            "van der berg",
            "van",
            "der",
            "berg",
        ]

    def test_missing_given_name_falls_back_to_family_only(self):
        """Display name is family-only when no given name is present."""
        payload = _build_payload(
            "0000-0002-1111-0000",
            {"family_name": "Plato"},
            [],
        )
        assert payload["name"] == "Plato"
        assert payload["props"]["display_name"] == "Plato"
        assert "name_parts" not in payload["props"]
        assert "given_name" not in payload

    def test_missing_both_names_falls_back_to_orcid(self):
        """Display name falls back to the bare ORCID when no name is present."""
        payload = _build_payload(
            "0000-0002-1111-0000",
            {},
            [],
        )
        assert payload["name"] == "0000-0002-1111-0000"
        assert payload["props"] == {"display_name": "0000-0002-1111-0000"}
        assert payload["tags"] == [KCNamesTag.CITED]
        assert "given_name" not in payload
        assert "family_name" not in payload

    def test_blank_affiliation_names_filtered_out(self):
        """Affiliations with empty/missing names are dropped from the payload."""
        payload = _build_payload(
            "0000-0002-1111-0000",
            {"family_name": "Doe"},
            [{"name": ""}, {"name": "  "}, {"name": "MIT"}, {"id": "x"}],
        )
        assert payload["affiliations"] == [{"name": "MIT"}]
        assert payload["props"]["family_phonetic_tokens"] == ["T"]

    def test_copies_kc_username_identifier_when_present(self):
        """A `kc_username` on `person_or_org` is copied into payload identifiers."""
        payload = _build_payload(
            "0000-0002-1825-0097",
            {
                "family_name": "Curie",
                "given_name": "Marie",
                "identifiers": [
                    {"scheme": "orcid", "identifier": "0000-0002-1825-0097"},
                    {"scheme": "kc_username", "identifier": "mcurie"},
                ],
            },
            [],
        )
        assert payload["identifiers"] == [
            {"scheme": "orcid", "identifier": "0000-0002-1825-0097"},
            {"scheme": "kc_username", "identifier": "mcurie"},
        ]

    def test_omits_blank_kc_username_identifier(self):
        """Blank `kc_username` values are not copied onto the payload."""
        payload = _build_payload(
            "0000-0002-1825-0097",
            {
                "family_name": "Curie",
                "identifiers": [
                    {"scheme": "kc_username", "identifier": "  "},
                ],
            },
            [],
        )
        assert payload["identifiers"] == [
            {"scheme": "orcid", "identifier": "0000-0002-1825-0097"},
        ]


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
    """`create` registers one post-commit task per ORCID-bearing person."""

    def test_no_data_is_a_no_op(self, app_ctx, component):
        """A `None` `data` argument short-circuits before UoW registration."""
        component.create(identity=None, data=None)
        component.uow.register.assert_not_called()

    def test_no_orcid_creators_is_a_no_op(self, app_ctx, component):
        """Drafts with creators but no ORCIDs register no tasks."""
        data = _data(creators=[_personal("Doe", "Jane")])
        component.create(identity=None, data=data)
        component.uow.register.assert_not_called()

    def test_registers_task_op_for_each_orcid_creator(self, app_ctx, component):
        """Each unique ORCID across creators+contributors yields one `TaskOp`."""
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

        ops = _registered_task_ops(component)
        assert len(ops) == 2
        assert [op._args[0]["id"] for op in ops] == [
            "0000-0002-1825-0097",
            "0000-0001-2345-6789",
        ]
        for op in ops:
            assert op._celery_task is upsert_cited_orcid_name_task
            assert op._kwargs == {"source": "creatibutor"}


class TestComponentUpdateDraft:
    """`update_draft` registers the same post-commit tasks as `create`."""

    def test_update_draft_dispatches_like_create(self, app_ctx, component):
        """`update_draft` registers one `TaskOp` per ORCID-bearing person."""
        data = _data(creators=[_personal("Curie", "Marie", "0000-0002-1825-0097")])
        component.update_draft(identity=None, data=data)
        ops = _registered_task_ops(component)
        assert len(ops) == 1
        assert ops[0]._celery_task is upsert_cited_orcid_name_task
        assert ops[0]._args[0]["id"] == "0000-0002-1825-0097"
