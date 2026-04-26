# Copyright (C) 2024-2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Service component that materializes Names records from ORCID-bearing creators.

When a deposit draft is saved (created or updated) with creators or contributors
carrying ORCID iDs, this component invokes
``NamesSyncService.upsert_cited_orcid_name(...)`` for each ORCID-identified person:

- If a ``kcworks-user`` Names record already carries that ORCID, the data is
  gap-filled into the user record (KC values win for scalar fields).
- Otherwise, a ``kcworks-cited`` stub is created (or refreshed) at PID = orcid.

The deposit-form picker (``invenio-modular-deposit-form``) puts ORCID-sourced
rows directly into ``metadata.creators[*].person_or_org`` with ``family_name``,
``given_name``, ``identifiers`` and ``affiliations``, so this component does no
ORCID API I/O — everything it needs is already in the draft data.

Failures from ``upsert_cited_orcid_name`` are logged but never propagated —
a Names side-effect must never fail a draft save.
"""

from typing import Any

from flask import current_app
from flask_principal import Identity
from invenio_drafts_resources.services.records.components import ServiceComponent

from ...proxies import current_names_sync_service


def _build_payload(
    bare_orcid: str,
    person_or_org: dict[str, Any],
    affiliations: list[dict[str, Any]],
) -> dict[str, Any]:
    """Assemble a ``NamesRecordDict``-shaped payload for ``upsert_cited_orcid_name``.

    The resulting dict's ``id`` is the bare ORCID (used as PID), and its
    contents are derived entirely from data already in the draft (no API I/O).
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


def _collect_orcid_payloads(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    """Build one Names payload per personal-type creator/contributor with an ORCID iD.

    Duplicate ORCIDs within a single draft are de-duplicated; only the first
    occurrence yields a payload.

    Returns:
        A list of ``NamesRecordDict``-shaped payloads (possibly empty).
    """
    entries = metadata.get("creators", []) + metadata.get("contributors", [])
    payloads: list[dict[str, Any]] = []
    seen_orcids: set[str] = set()
    for entry in entries:
        person_or_org = entry["person_or_org"]
        # ORCID iDs only make sense for personal entries; orgs may carry an
        # ORCID-shaped identifier by accident but shouldn't yield a Names person.
        if person_or_org["type"] != "personal":
            continue
        ids = person_or_org.get("identifiers", [])
        orcid = next((i["identifier"] for i in ids if i["scheme"] == "orcid"), "")

        if not orcid or orcid in seen_orcids:
            continue
        seen_orcids.add(orcid)
        payloads.append(
            _build_payload(orcid, person_or_org, entry.get("affiliations", []))
        )
    return payloads


class CitedNamesUpsertComponent(ServiceComponent):
    """Upsert Names records for ORCID-identified creators/contributors on draft save."""

    def create(
        self, identity: Identity, data: dict | None = None, **kwargs: Any
    ) -> None:
        """Scan a freshly-created draft and upsert Names for ORCID persons."""
        self._scan_and_upsert(data)

    def update_draft(
        self, identity: Identity, data: dict | None = None, **kwargs: Any
    ) -> None:
        """Scan an updated draft and upsert Names for ORCID persons."""
        self._scan_and_upsert(data)

    def _scan_and_upsert(self, data: dict | None) -> None:
        """Build ORCID payloads from ``data`` and upsert each via the Names service."""
        if not data:
            return
        payloads = _collect_orcid_payloads(data["metadata"])
        for payload in payloads:
            try:
                current_names_sync_service.upsert_cited_orcid_name(
                    payload, source="creatibutor"
                )
            except Exception:
                # Names side-effects MUST NOT fail a draft save. Log and move on.
                current_app.logger.exception(
                    "CitedNamesUpsertComponent: upsert_cited_orcid_name failed for "
                    "ORCID %s",
                    payload["id"],
                )
