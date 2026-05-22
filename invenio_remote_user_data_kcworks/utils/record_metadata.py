# Copyright (C) 2024-2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Pure helpers that operate on RDM record metadata dicts.

Anything in this module is a pure-Python walker / mutator over a
`metadata` sub-dict (or one of its lists). No I/O, no app context, no
Names / RDM service calls. The companion service in
`services.record_username_sync` is responsible for the orchestration
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

from __future__ import annotations

from typing import Any


def _rewrite_in_list(
    entries: list[dict[str, Any]],
    *,
    old_username: str,
    new_username: str,
) -> bool:
    """Rewrite the kc_username identifier in a list of creator/contributor entries.

    Iterates `entries` in place; for each personal-type entry whose
    `person_or_org.identifiers` list contains an item with
    `scheme == "kc_username"` and `identifier == old_username`, replace the
    `identifier` value with `new_username`.

    Args:
        entries: A list of creator or contributor entry dicts (e.g.
            `metadata.get("creators", [])`).
        old_username: The pre-rename KC username to replace.
        new_username: The post-rename KC username to write in its place.

    Returns:
        `True` if at least one identifier value was rewritten; `False`
        otherwise.
    """
    changed = False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        person_or_org = entry.get("person_or_org")
        if not isinstance(person_or_org, dict):
            continue
        if person_or_org.get("type") != "personal":
            continue
        identifiers = person_or_org.get("identifiers")
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

    creators_changed = _rewrite_in_list(
        metadata.get("creators") or [],
        old_username=old_username,
        new_username=new_username,
    )
    contributors_changed = _rewrite_in_list(
        metadata.get("contributors") or [],
        old_username=old_username,
        new_username=new_username,
    )
    return creators_changed or contributors_changed
