# Copyright (C) 2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Tests for `UserProfileService` display_name helpers and backfill."""

import json

from invenio_db import db

from invenio_remote_user_data_kcworks.services.user_profile import UserProfileService


def _set_profile(user, **fields):
    profile = dict(user.user_profile or {})
    profile.update(fields)
    user.user_profile = profile
    db.session.commit()
    return user


def test_get_user_name_variants_prefers_stored_display_and_full_name(user_factory):
    """Stored `full_name` / `display_name` win over composed name parts."""
    u = user_factory(email="variants@example.org", kc_username="variants_user")
    parts = json.dumps({"first": "Marie", "last": "Curie"})
    _set_profile(
        u.user,
        full_name="Marie Skłodowska Curie",
        display_name="Curie, Marie Skłodowska",
        name_parts=parts,
    )

    variants = UserProfileService.get_user_name_variants(u.user.id, u.user.user_profile)

    assert variants["full_name"] == "Marie Skłodowska Curie"
    assert variants["display_name"] == "Curie, Marie Skłodowska"


def test_get_user_name_variants_composes_when_stored_missing(user_factory):
    """Missing stored names fall back to composed full/inverted forms."""
    u = user_factory(email="compose@example.org", kc_username="compose_user")
    parts = json.dumps({"first": "Ada", "last": "Lovelace"})
    _set_profile(u.user, name_parts=parts)

    variants = UserProfileService.get_user_name_variants(u.user.id, u.user.user_profile)

    assert variants["full_name"] == "Ada Lovelace"
    assert variants["display_name"] == "Lovelace, Ada"


def test_get_user_name_variants_includes_aliases_when_parts_differ(user_factory):
    """Composed forms that differ from stored values become aliases."""
    u = user_factory(email="alias@example.org", kc_username="alias_user")
    parts = json.dumps({"first": "Marie", "last": "Curie"})
    _set_profile(
        u.user,
        full_name="Marie Skłodowska Curie",
        display_name="Curie, Marie Skłodowska",
        name_parts=parts,
    )

    variants = UserProfileService.get_user_name_variants(u.user.id, u.user.user_profile)
    aliases = variants.get("name_aliases") or []

    assert "Marie Curie" in aliases
    assert "Curie, Marie" in aliases


def test_compute_display_name_prefers_name_parts_local(user_factory):
    """Local name parts override remote parts for composed display_name."""
    u = user_factory(email="localparts@example.org", kc_username="localparts")
    _set_profile(
        u.user,
        name_parts=json.dumps({"first": "Remote", "last": "RemoteFamily"}),
        name_parts_local=json.dumps({"first": "Local", "last": "LocalFamily"}),
    )

    assert (
        UserProfileService.compute_display_name_from_profile(u.user.user_profile)
        == "LocalFamily, Local"
    )


def test_update_local_name_parts_refreshes_display_name(user_factory):
    """Editing local name parts persists inverted `display_name`."""
    u = user_factory(email="editparts@example.org", kc_username="editparts")
    updated = UserProfileService.update_local_name_parts(
        u.user.id,
        {"first": "Grace", "last": "Hopper"},
    )

    assert updated.user_profile["display_name"] == "Hopper, Grace"
    assert json.loads(updated.user_profile["name_parts_local"]) == {
        "first": "Grace",
        "last": "Hopper",
    }


def test_backfill_display_names_fills_empty_only(user_factory):
    """Default backfill writes empty `display_name`; skips existing unless force."""
    empty = user_factory(
        email="bf_empty@example.org",
        kc_username="bf_empty",
        oauth_id="bf-empty-oauth",
    )
    _set_profile(
        empty.user,
        name_parts=json.dumps({"first": "Empty", "last": "Slot"}),
    )
    kept = user_factory(
        email="bf_kept@example.org",
        kc_username="bf_kept",
        oauth_id="bf-kept-oauth",
    )
    _set_profile(
        kept.user,
        display_name="Kept, Custom",
        name_parts=json.dumps({"first": "Kept", "last": "Custom"}),
    )

    dry = UserProfileService.backfill_display_names(dry_run=True)
    assert dry["updated"] >= 1

    stats = UserProfileService.backfill_display_names(dry_run=False)
    assert stats["updated"] >= 1

    db.session.refresh(empty.user)
    db.session.refresh(kept.user)
    assert empty.user.user_profile.get("display_name") == "Slot, Empty"
    assert kept.user.user_profile.get("display_name") == "Kept, Custom"

    forced = UserProfileService.backfill_display_names(dry_run=False, force=True)
    assert forced["updated"] >= 1
    db.session.refresh(kept.user)
    assert kept.user.user_profile.get("display_name") == "Custom, Kept"
