# Copyright (C) 2024-2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Service component that queues Names upserts from ORCID-bearing creators.

When a deposit draft is saved (created or updated) with creators or contributors
carrying ORCID iDs, this component collects ORCID payloads and registers a
`TaskOp` per person so `NamesSyncService.upsert_cited_orcid_name(...)` runs
**after** the draft unit of work commits:

- If a `kcworks-user` Names record already carries that ORCID, the data is
  gap-filled into the user record (KC values win for scalar fields).
- Otherwise, a `kcworks-cited` stub is created (or refreshed) at PID = orcid.

Running Names work in a Celery task (via `TaskOp.on_post_commit`) keeps it out
of the draft create/update SQLAlchemy session: a Names failure cannot
`session.rollback()` an in-flight draft parent. Failed draft UoWs never
enqueue.

The deposit-form picker (`invenio-modular-deposit-form`) puts ORCID-sourced
rows directly into `metadata.creators[*].person_or_org` with `family_name`,
`given_name`, `identifiers` and `affiliations`, so this component does no
ORCID API I/O — everything it needs is already in the draft data.
"""

from typing import Any

from flask_principal import Identity
from invenio_drafts_resources.services.records.components import ServiceComponent
from invenio_rdm_records.records.api import RDMRecord
from invenio_records_resources.services.uow import TaskOp

from ...tasks import upsert_cited_orcid_name_task
from ...utils.orcid_payload import collect_orcid_payloads


class CitedNamesUpsertComponent(ServiceComponent):
    """Queue Names upserts for ORCID-identified creators/contributors on draft save."""

    def create(
        self, identity: Identity, data: dict | None = None, **kwargs: Any
    ) -> None:
        """Enqueue Names upserts after a successful draft create commit."""
        self._enqueue_cited_names(data)

    def update_draft(
        self,
        identity: Identity,
        data: dict | None = None,
        record: RDMRecord | None = None,
        errors: dict[str, Any] | None = None,
    ) -> None:
        """Enqueue Names upserts after a successful draft update commit."""
        self._enqueue_cited_names(data)

    def _enqueue_cited_names(self, data: dict | None) -> None:
        """Register a post-commit Celery task per ORCID payload in ``data``.

        Args:
            data: Draft service payload (must include ``metadata`` when present).
        """
        if not data:
            return
        for payload in collect_orcid_payloads(data["metadata"]):
            self.uow.register(
                TaskOp(
                    upsert_cited_orcid_name_task,
                    payload,
                    source="creatibutor",
                )
            )
