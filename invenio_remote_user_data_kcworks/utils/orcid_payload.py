# Copyright (C) 2024-2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Shared helpers for assembling ORCID-derived Names payloads.

These helpers live in their own module so the on-draft-save service component
(`CitedNamesUpsertComponent` in
`...services.components.cited_names_component`) and the published-record
backfill on `NamesSyncService` (in `...services.names_sync`) share one
implementation.

Both helpers read draft-shaped or record-shaped metadata and produce
`NamesRecordDict`-shaped payloads that the Names sync service knows how to
upsert.
"""

from typing import Any


def build_orcid_payload(
    bare_orcid: str,
    person_or_org: dict[str, Any],
    affiliations: list[dict[str, Any]],
) -> dict[str, Any]:
    """Assemble a `NamesRecordDict`-shaped payload for `upsert_cited_orcid_name`.

    The resulting dict's `id` is the bare ORCID (used as PID), and its
    contents are derived entirely from data already in the source record
    (no API I/O).

    Args:
        bare_orcid: The bare ORCID iD (e.g. `"0000-0001-2345-6789"`).
        person_or_org: A `person_or_org` sub-dict from a creator or
            contributor entry.
        affiliations: The sibling `affiliations` list from the same entry.

    Returns:
        A dict shaped like `NamesRecordDict`, suitable to pass to
        `NamesSyncService.upsert_cited_orcid_name`.
    """
    family = person_or_org.get("family_name", "").strip()
    given = person_or_org.get("given_name", "").strip()
    full_name = person_or_org.get("name", "").strip()
    display_name = full_name or ", ".join(p for p in (family, given) if p) or bare_orcid
    affiliation_names = [a.get("name", "").strip() for a in affiliations]
    return {
        "id": bare_orcid,
        "given_name": given,
        "family_name": family,
        "name": display_name,
        "identifiers": [{"scheme": "orcid", "identifier": bare_orcid}],
        "affiliations": [{"name": n} for n in affiliation_names if n],
    }


def collect_orcid_payloads(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    """Build one Names payload per personal-type creator/contributor with an ORCID iD.

    Duplicate ORCIDs within a single record are de-duplicated; only the first
    occurrence yields a payload. Organizational entries are skipped even if
    they accidentally carry an ORCID-shaped identifier.

    Args:
        metadata: The `metadata` sub-dict of a draft or published record.

    Returns:
        A list of `NamesRecordDict`-shaped payloads (possibly empty).
    """
    entries = metadata.get("creators", []) + metadata.get("contributors", [])
    payloads: list[dict[str, Any]] = []
    seen_orcids: set[str] = set()
    for entry in entries:
        person_or_org = entry["person_or_org"]
        if person_or_org["type"] != "personal":
            continue
        ids = person_or_org.get("identifiers", [])
        orcid = next((i["identifier"] for i in ids if i["scheme"] == "orcid"), "")

        if not orcid or orcid in seen_orcids:
            continue
        seen_orcids.add(orcid)
        payloads.append(
            build_orcid_payload(orcid, person_or_org, entry.get("affiliations", []))
        )
    return payloads
