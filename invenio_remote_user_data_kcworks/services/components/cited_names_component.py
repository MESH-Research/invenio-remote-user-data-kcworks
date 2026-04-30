# Copyright (C) 2024-2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Service component that creates or updates Names records from ORCID-bearing creators.

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
from invenio_rdm_records.records.api import RDMRecord

from ...proxies import current_names_sync_service
from ...utils.orcid_payload import collect_orcid_payloads


class CitedNamesUpsertComponent(ServiceComponent):
    """Upsert Names records for ORCID-identified creators/contributors on draft save."""

    def create(
        self, identity: Identity, data: dict | None = None, **kwargs: Any
    ) -> None:
        """Scan a freshly-created draft and upsert Names for ORCID persons."""
        self._scan_and_upsert(data)

    def update_draft(
        self,
        identity: Identity,
        data: dict | None = None,
        record: RDMRecord | None = None,
        errors: dict[str, Any] | None = None,
    ) -> None:
        """Scan an updated draft and upsert Names for ORCID persons."""
        self._scan_and_upsert(data)

    def _scan_and_upsert(self, data: dict | None) -> None:
        """Build ORCID payloads from ``data`` and upsert each via the Names service."""
        if not data:
            return
        payloads = collect_orcid_payloads(data["metadata"])
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
