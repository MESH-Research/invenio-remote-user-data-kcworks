# Copyright (C) 2024-2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Behavioural tests for `NamesSyncService` payload builders and upsert seams.

This module complements:

* `test_names_sync.py` — duplicate-candidate scoring over synthetic corpora.
* `test_names_sync_backfill.py` — `backfill_cited_orcid_from_records` over RDM
  metadata dicts.

Here we assert **observable outcomes** from `build_name_payload_from_user` and
from `upsert_name_for_user` with the Names service and merge paths mocked, so
no live Names/OpenSearch binding is required.

See Also:
    This package `docs/private/functionality-test-remediation-plan.md`
    (planning + coverage gaps; canonical path under dependency root).
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, PropertyMock

import pytest
from invenio_pidstore.errors import PIDAlreadyExists

from invenio_remote_user_data_kcworks.config import KCNamesTag
from invenio_remote_user_data_kcworks.services.names_sync import NamesSyncService


@pytest.fixture()
def service(base_app) -> NamesSyncService:
    """Return a `NamesSyncService` bound to the pytest-invenio `base_app`.

    Args:
        base_app: Minimal Flask app from pytest-invenio.

    Returns:
        A fresh service instance (no registry access until `names_service` or
        upsert paths run).
    """
    return NamesSyncService(base_app)


def _user(
    *,
    user_id: int = 1,
    username: str = "",
    email: str = "",
    user_profile: dict[str, Any] | None = None,
) -> SimpleNamespace:
    """Build a duck-typed user object for payload / upsert tests.

    Args:
        user_id: Primary key used in `internal_id` / props.
        username: Login name (fallback display when name parts absent).
        email: Email (local-part fallback when username empty).
        user_profile: Serialized `user_profile` blob; copied shallowly.

    Returns:
        A `SimpleNamespace` exposing the attributes `NamesSyncService` reads
        from `invenio_accounts.models.User`.
    """
    return SimpleNamespace(
        id=user_id,
        username=username,
        email=email,
        user_profile=dict(user_profile or {}),
    )


@pytest.mark.usefixtures("base_app")
class TestBuildNamePayloadFromUser:
    """Tests for `NamesSyncService.build_name_payload_from_user`."""

    def test_returns_none_when_user_missing(self, service: NamesSyncService):
        """Missing `user` yields `None` without reading profile."""
        assert service.build_name_payload_from_user(None) is None

    def test_fallback_display_uses_username_when_no_name_parts(
        self, service: NamesSyncService
    ):
        """With only `identifier_kc_username`, display falls back to username."""
        user = _user(
            username="fallbackuser",
            email="ignored@example.org",
            user_profile={"identifier_kc_username": "kcslug"},
        )
        payload = service.build_name_payload_from_user(user)
        assert payload is not None
        assert payload["id"] == "kcslug"
        assert payload["name"] == "fallbackuser"
        assert payload["props"]["kcworks_user_id"] == "1"
        assert KCNamesTag.USER in payload["tags"]

    def test_fallback_display_uses_email_local_part_when_username_empty(
        self, service: NamesSyncService
    ):
        """When username is empty, the email local-part backs the display name."""
        user = _user(
            username="",
            email="localpart@example.org",
            user_profile={"identifier_kc_username": "kcslug"},
        )
        payload = service.build_name_payload_from_user(user)
        assert payload is not None
        assert payload["name"] == "localpart"

    def test_name_parts_local_overrides_remote_for_structured_fields(
        self, service: NamesSyncService
    ):
        """`name_parts_local` wins over `name_parts` for given/family extraction."""
        remote = json.dumps({"first": "Remote", "family": "RemoteFamily"})
        local = {"first": "LocalFirst", "family": "LocalFamily"}
        user = _user(
            user_profile={
                "identifier_kc_username": "kcslug",
                "name_parts": remote,
                "name_parts_local": local,
            },
        )
        payload = service.build_name_payload_from_user(user)
        assert payload is not None
        assert payload["given_name"] == "LocalFirst"
        assert payload["family_name"] == "LocalFamily"
        assert payload["props"]["name_parts"] == local
        assert "LocalFamily" in (payload["props"].get("display_name") or "")

    def test_invalid_name_parts_json_falls_back_to_username(
        self, service: NamesSyncService
    ):
        """Broken JSON in `name_parts` is ignored; display still satisfies schema."""
        user = _user(
            username="jsonbroken",
            user_profile={
                "identifier_kc_username": "kcslug",
                "name_parts": "not-json{{{",
            },
        )
        payload = service.build_name_payload_from_user(user)
        assert payload is not None
        assert payload["name"] == "jsonbroken"
        assert "name_parts" not in payload["props"]

    def test_identifiers_include_kc_username_and_orcid(
        self, service: NamesSyncService
    ):
        """Both schemes appear when profile carries KC username and ORCID."""
        user = _user(
            user_profile={
                "identifier_kc_username": "jdoe",
                "identifier_orcid": "0000-0002-1825-0097",
            },
        )
        payload = service.build_name_payload_from_user(user)
        assert payload is not None
        schemes = {i["scheme"]: i["identifier"] for i in payload["identifiers"]}
        assert schemes["kc_username"] == "jdoe"
        assert schemes["orcid"] == "0000-0002-1825-0097"

    def test_affiliation_only_when_string(self, service: NamesSyncService):
        """Non-string `affiliations` yields an empty list (no bogus entries)."""
        user = _user(
            username="u",
            user_profile={
                "identifier_kc_username": "kcslug",
                "affiliations": ["not-a-string"],
            },
        )
        payload = service.build_name_payload_from_user(user)
        assert payload is not None
        assert payload["affiliations"] == []

    def test_family_dedup_props_for_simple_family(self, service: NamesSyncService):
        """Single-piece family names populate token + phonetic dedup props."""
        user = _user(
            username="u",
            user_profile={
                "identifier_kc_username": "kcslug",
                "name_parts": json.dumps({"first": "Pat", "family": "Smith"}),
            },
        )
        payload = service.build_name_payload_from_user(user)
        assert payload is not None
        assert payload["props"]["family_token"] == "smith"
        assert payload["props"]["family_part_tokens"] == ["smith"]
        assert payload["props"]["family_phonetic_tokens"] == ["SM0"]

    def test_family_dedup_props_for_compound_family(self, service: NamesSyncService):
        """Hyphenated / multi-piece families yield ordered part + phonetic tokens."""
        user = _user(
            username="u",
            user_profile={
                "identifier_kc_username": "kcslug",
                "name_parts": json.dumps({"first": "A", "family": "García-López"}),
            },
        )
        payload = service.build_name_payload_from_user(user)
        assert payload is not None
        parts = payload["props"]["family_part_tokens"]
        assert parts[0] == "garcia lopez"
        assert "garcia" in parts
        assert "lopez" in parts
        assert payload["props"]["family_phonetic_tokens"]


@pytest.mark.usefixtures("base_app")
class TestUpsertNameForUser:
    """Tests for `NamesSyncService.upsert_name_for_user` with mocked Names I/O."""

    def test_returns_none_when_user_missing(self, service: NamesSyncService):
        """Guards before payload build: no Names registry access."""
        assert service.upsert_name_for_user(None) is None

    def test_create_called_when_no_existing_record(
        self, base_app, service: NamesSyncService, monkeypatch: pytest.MonkeyPatch
    ):
        """`_read_existing` miss leads to `create` with payload PID."""
        names = MagicMock()
        item = MagicMock()
        item.to_dict.return_value = {"id": "jdoe", "tags": [KCNamesTag.USER]}
        names.create.return_value = item
        monkeypatch.setattr(
            NamesSyncService,
            "names_service",
            PropertyMock(return_value=names),
        )
        monkeypatch.setattr(service, "_read_existing", lambda _id, pid: None)

        user = _user(
            username="jdoe",
            user_profile={"identifier_kc_username": "jdoe"},
        )
        with base_app.app_context():
            out = service.upsert_name_for_user(user)

        assert out == {"id": "jdoe", "tags": [KCNamesTag.USER]}
        names.create.assert_called_once()
        names.update.assert_not_called()
        _identity, payload_arg = names.create.call_args[0]
        assert payload_arg["id"] == "jdoe"

    def test_update_called_when_record_exists(
        self, base_app, service: NamesSyncService, monkeypatch: pytest.MonkeyPatch
    ):
        """Existing PID short-circuits to `update`, not `create`."""
        names = MagicMock()
        item = MagicMock()
        item.to_dict.return_value = {"id": "jdoe"}
        names.update.return_value = item
        monkeypatch.setattr(
            NamesSyncService,
            "names_service",
            PropertyMock(return_value=names),
        )
        monkeypatch.setattr(service, "_read_existing", lambda _id, pid: object())

        user = _user(
            username="jdoe",
            user_profile={"identifier_kc_username": "jdoe"},
        )
        with base_app.app_context():
            out = service.upsert_name_for_user(user)

        assert out == {"id": "jdoe"}
        names.update.assert_called_once()
        names.create.assert_not_called()

    def test_pid_race_retries_update(
        self, base_app, service: NamesSyncService, monkeypatch: pytest.MonkeyPatch
    ):
        """`PIDAlreadyExists` on create is followed by a single `update`."""
        names = MagicMock()
        item = MagicMock()
        item.to_dict.return_value = {"id": "jdoe", "recovered": True}
        names.create.side_effect = PIDAlreadyExists("kc_username", "jdoe")
        names.update.return_value = item
        monkeypatch.setattr(
            NamesSyncService,
            "names_service",
            PropertyMock(return_value=names),
        )
        monkeypatch.setattr(service, "_read_existing", lambda _id, pid: None)

        user = _user(
            username="jdoe",
            user_profile={"identifier_kc_username": "jdoe"},
        )
        with base_app.app_context():
            out = service.upsert_name_for_user(user)

        assert out["recovered"] is True
        names.create.assert_called_once()
        names.update.assert_called_once()
