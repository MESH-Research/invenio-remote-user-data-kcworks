# Copyright (C) 2024-2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Pure helpers that operate on RDM record metadata dicts.

Anything in this module is a pure-Python walker / mutator over a
`metadata` sub-dict (or one of its lists). No I/O, no app context, no
Names / RDM service calls. The companion service in
`services.record_creatibutor_sync` is responsible for the orchestration
side: searching for records, opening drafts via `edit()`, calling
`update_draft` / `publish`, and accumulating per-pass stats.

The shape these helpers walk matches the shape that
`utils.orcid_payload.collect_orcid_payloads` walks:
`metadata.creators[*]` plus `metadata.contributors[*]`, each entry's
`person_or_org` block carrying an `identifiers` list of
`{"scheme", "identifier"}` dicts. Only personal-type entries are
touched — organizational entries with a coincidental
`kc_username`-shaped identifier are skipped to mirror the upstream
contract.

Add new pure metadata utilities to this module rather than creating
another helper file; that keeps the metadata-related surface in one
place.
"""

from collections.abc import Iterator
from typing import Any


def _iter_personal_person_or_org(
    metadata: dict[str, Any],
) -> Iterator[dict[str, Any]]:
    """Yield personal `person_or_org` dicts from creators and contributors.

    Skips non-dict metadata, non-list entry lists, non-dict entries, and
    non-personal `person_or_org` blocks.

    Args:
        metadata: Record `metadata` dict.

    Yields:
        Mutable `person_or_org` dicts with `type == "personal"`.
    """
    for key in ("creators", "contributors"):
        entries = metadata.get(key)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            person = entry.get("person_or_org")
            if not isinstance(person, dict) or person.get("type") != "personal":
                continue
            yield person


def _identifiers_include(
    identifiers: Any,
    wanted: set[tuple[str, str]],
) -> bool:
    """Whether an identifiers list contains any `(scheme, identifier)` in wanted.

    Args:
        identifiers: Creatibutor `identifiers` value (usually a list of dicts).
        wanted: Set of `(scheme, identifier)` pairs to match.

    Returns:
        `True` if any identifier dict matches a wanted pair.
    """
    if not isinstance(identifiers, list):
        return False
    for ident in identifiers:
        if not isinstance(ident, dict):
            continue
        pair = (ident.get("scheme") or "", ident.get("identifier") or "")
        if pair in wanted:
            return True
    return False


def rewrite_kc_username(
    metadata: dict[str, Any],
    *,
    old_username: str,
    new_username: str,
) -> bool:
    """Rewrite kc_username identifiers in a record's creators and contributors.

    Walks `metadata["creators"]` and `metadata["contributors"]` and, for each
    personal-type `person_or_org` whose `identifiers` list carries an entry
    with `scheme == "kc_username"` and `identifier == old_username`, replaces
    the identifier value with `new_username`. The mutation is in place.

    The match is case-sensitive on both `scheme` and `identifier` to mirror
    `UserSearchHelper` and the deposit-form picker.

    Args:
        metadata: The `metadata` sub-dict of a draft or published record
            (mutated in place).
        old_username: The pre-rename KC username to replace.
        new_username: The post-rename KC username to write in its place.

    Returns:
        `True` if any identifier was rewritten in either list; `False`
        otherwise (no-op cases include: no matching entry, or `metadata`
        not shaped as expected).
    """
    if not isinstance(metadata, dict):
        return False
    if not old_username or not new_username or old_username == new_username:
        return False

    changed = False
    for person in _iter_personal_person_or_org(metadata):
        identifiers = person.get("identifiers")
        if not isinstance(identifiers, list):
            continue
        for ident in identifiers:
            if not isinstance(ident, dict):
                continue
            if (
                ident.get("scheme") == "kc_username"
                and ident.get("identifier") == old_username
            ):
                ident["identifier"] = new_username
                changed = True
    return changed


# Profile field → creatibutor identifier scheme (deposit form convention).
_PROFILE_IDENTIFIER_FIELDS: tuple[tuple[str, str], ...] = (
    ("identifier_kc_username", "kc_username"),
    ("identifier_orcid", "orcid"),
    ("identifier_email", "email"),
)


def user_identifier_pairs(profile: dict[str, Any]) -> list[tuple[str, str]]:
    """Return `(scheme, identifier)` pairs from a user profile.

    Args:
        profile: A `user_profile` dict.

    Returns:
        Non-empty identifier pairs suitable for matching creatibutors.
    """
    pairs: list[tuple[str, str]] = []
    for field, scheme in _PROFILE_IDENTIFIER_FIELDS:
        value = (profile.get(field) or "").strip()
        if value:
            pairs.append((scheme, value))
    return pairs


def rewrite_creatibutor_display_names(
    metadata: dict[str, Any],
    *,
    display_name: str,
    id_pairs: list[tuple[str, str]],
) -> bool:
    """Set matching personal creatibutors' `name` to `display_name`.

    Only personal entries whose identifiers include one of `id_pairs` are
    updated, and only when the current `name` differs.

    Args:
        metadata: Record `metadata` dict (mutated in place).
        display_name: Target bibliographic/inverted display string.
        id_pairs: `(scheme, identifier)` pairs that identify the user.

    Returns:
        `True` if any entry was changed.
    """
    if not isinstance(metadata, dict):
        return False
    if not display_name or not id_pairs:
        return False
    wanted = {(scheme, ident) for scheme, ident in id_pairs}
    changed = False
    for person in _iter_personal_person_or_org(metadata):
        if not _identifiers_include(person.get("identifiers"), wanted):
            continue
        current = (person.get("name") or "").strip()
        if current == display_name:
            continue
        person["name"] = display_name
        changed = True
    return changed
