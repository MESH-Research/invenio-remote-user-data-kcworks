# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""Narrow unit tests for remote→local mapping in `CILogonHelpers` (no I/O, no DB).

Uses `base_app` + `app_context` only—no full `app` / search fixtures.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

from invenio_remote_user_data_kcworks.types.profiles_api import (
    APIResponse,
    Group,
    Meta,
    SubData,
)
from invenio_remote_user_data_kcworks.utils.auth import CILogonHelpers
from tests.fixtures.idms import minimal_api_response, minimal_profile


def _mock_user(
    *,
    username: str = "local_u",
    email: str = "local@example.org",
    user_profile: dict | None = None,
    preferences: dict | None = None,
    roles: list | None = None,
) -> MagicMock:
    """Return a `MagicMock` with the attributes `calculate_user_changes` reads."""
    user = MagicMock()
    user.id = 42
    user.username = username
    user.email = email
    user.active = True
    user.user_profile = dict(user_profile or {})
    user.preferences = dict(
        preferences
        or {
            "visibility": "restricted",
            "email_visibility": "restricted",
            "locale": "en",
        }
    )
    user.roles = roles if roles is not None else []
    return user


def test_calculate_user_changes_maps_core_fields_from_api_response(base_app):
    """Remote profile overwrites username, email, profile slices, and visibility."""
    with base_app.app_context():
        api = minimal_api_response(
            "sub-1",
            username="remote_u",
            name="Remote Name",
            email="remote@example.org",
            first_name="Remote",
            last_name="Name",
            institutional_affiliation="Some University",
            orcid="0000-0001-0002-0003",
            groups=[],
        )
        user = _mock_user(username="old_u", email="old@example.org")
        changes, new_data = CILogonHelpers.calculate_user_changes(api, user)

        assert new_data["username"] == "remote_u"
        assert new_data["email"] == "remote@example.org"
        assert new_data["user_profile"]["identifier_kc_username"] == "remote_u"
        assert new_data["user_profile"]["full_name"] == "Remote Name"
        assert json.loads(new_data["user_profile"]["name_parts"]) == {
            "first": "Remote",
            "last": "Name",
        }
        assert new_data["user_profile"]["affiliations"] == "Some University"
        assert new_data["user_profile"]["identifier_orcid"] == "0000-0001-0002-0003"
        assert new_data["preferences"]["visibility"] == "public"
        assert new_data["preferences"]["email_visibility"] == "public"

        assert changes["username"] == "remote_u"
        assert changes["email"] == "remote@example.org"
        assert "user_profile" in changes
        # `calculate_user_changes` mutates `user.preferences` in place after capturing
        # `initial_user_data`, so the sparse diff often omits `preferences` even when
        # `new_data["preferences"]` reflects public visibility (see assertions above).


def test_calculate_user_changes_accepts_plain_profile_same_as_wrapped(base_app):
    """`Profile` and single-row `APIResponse` yield identical `new_data`."""
    with base_app.app_context():
        prof = minimal_profile(
            username="plain",
            name="Plain User",
            email="plain@example.org",
            first_name="Pl",
            last_name="ain",
            institutional_affiliation=None,
            orcid=None,
            groups=[],
        )
        api = APIResponse(
            data=[SubData(sub="s", profile=prof)],
            meta=Meta(authorized=True),
            next=None,
            previous=None,
        )
        user = _mock_user()
        _, from_profile = CILogonHelpers.calculate_user_changes(prof, user)
        user2 = _mock_user()
        _, from_api = CILogonHelpers.calculate_user_changes(api, user2)

        assert from_profile["username"] == from_api["username"] == "plain"
        assert from_profile["email"] == from_api["email"]
        assert (
            from_profile["user_profile"]["identifier_kc_username"]
            == from_api["user_profile"]["identifier_kc_username"]
        )


def test_calculate_user_changes_overwrites_orcid_from_remote(base_app):
    """When Profiles sends a non-empty ORCID, it becomes `identifier_orcid`."""
    with base_app.app_context():
        api = minimal_api_response(
            "sub-x",
            username="u",
            name="N",
            email="n@example.org",
            first_name="N",
            last_name="U",
            orcid="0000-0001-0002-0003",
            groups=[],
        )
        user = _mock_user(user_profile={"identifier_orcid": "0000-0000-0000-0000"})
        _, new_data = CILogonHelpers.calculate_user_changes(api, user)

        assert new_data["user_profile"]["identifier_orcid"] == "0000-0001-0002-0003"


def test_calculate_user_changes_keeps_local_affiliation_when_remote_blank(base_app):
    """Merged profile keeps prior affiliations when remote sends none."""
    with base_app.app_context():
        api = minimal_api_response(
            "sub-x",
            username="u",
            name="N",
            email="n@example.org",
            first_name="N",
            last_name="U",
            institutional_affiliation=None,
            orcid="",
            groups=[],
        )
        user = _mock_user(
            user_profile={"affiliations": "Prior University", "extra": "kept"},
        )
        _, new_data = CILogonHelpers.calculate_user_changes(api, user)

        assert new_data["user_profile"]["affiliations"] == "Prior University"
        assert new_data["user_profile"]["extra"] == "kept"


def test_calculate_group_changes_builds_role_strings_and_superadmin_roles(base_app):
    """Map group id/role to KC role strings; superadmin adds two admin roles."""
    with base_app.app_context():
        profile = minimal_profile(
            username="g",
            name="G",
            email="g@example.org",
            groups=[
                Group(id=1000551, group_name="DH", role="member"),
                Group(id=1000576, group_name="T", role="administrator"),
            ],
            is_superadmin=True,
        )
        user = _mock_user(
            roles=[
                SimpleNamespace(name="admin"),
            ]
        )

        gc = CILogonHelpers.calculate_group_changes(profile, user)

        assert set(gc["added_groups"]) >= {
            "knowledgeCommons---1000551|member",
            "knowledgeCommons---1000576|administrator",
            "administration",
            "administration-moderation",
        }
        assert "admin" in gc["unchanged_groups"]
        assert gc["dropped_groups"] == []


def test_calculate_group_changes_no_delta_when_remote_matches_local_kc_roles(base_app):
    """When local KC roles match remote, added/dropped are empty."""
    with base_app.app_context():
        profile = minimal_profile(
            username="g",
            groups=[
                Group(id=1, group_name="A", role="member"),
            ],
        )
        user = _mock_user(
            roles=[
                SimpleNamespace(name="knowledgeCommons---1|member"),
            ]
        )

        gc = CILogonHelpers.calculate_group_changes(profile, user)

        assert gc["added_groups"] == []
        assert gc["dropped_groups"] == []
        assert gc["unchanged_groups"] == ["knowledgeCommons---1|member"]
