# Copyright (C) 2024-2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Service for propagating a KC username rename through RDM records.

After a Profiles `updated` webhook flips a user's `kc_username`, every
record (published or draft) that cited the old username in a
`metadata.creators[*]` or `metadata.contributors[*]` block becomes stale.
The link from the record back to the user lives in the `identifiers` list,
shaped `{"scheme": "kc_username", "identifier": "<username>"}`; we rewrite
those values to the new username so search / display / mention paths keep
resolving.

Why a dedicated service rather than a bare function:

- Published records: `edit() -> update_draft() -> publish()` per match,
  iterated via `scan()` for unbounded result sets. Each `publish()` cycles
  the record through indexers and any publish-time hooks (DataCite,
  remote-API provisioner, stats); that's the same path a manual edit
  would take, so it is intentional.
- Drafts: scanned through the RDM records service's search machinery
  with the draft search configuration, then patched with `update_draft`
  (no publish — drafts stay drafts; their owner may publish later).
- Per-record errors are caught, counted, and logged. One bad record
  must never strand the rest of the corpus, mirroring how
  `NamesSyncService.backfill_cited_orcid_from_records` and
  `CitedNamesUpsertComponent` swallow per-item failures.

The pure rewrite step lives in `utils.record_metadata.rewrite_kc_username`
so it can be unit-tested without I/O.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from flask_principal import Identity
from invenio_access.permissions import system_identity
from invenio_rdm_records.proxies import current_rdm_records_service
from invenio_records_resources.services import Service
from invenio_search.engine import dsl

from ..utils.record_metadata import rewrite_kc_username

__all__ = ("RecordKcUsernameSyncService",)


class RecordKcUsernameSyncService(Service):
    """Rewrite kc_username identifiers across published records and drafts.

    Construct once at app init via `InvenioRemoteUserData` and access elsewhere
    via the `current_record_kc_username_sync_service` proxy.
    """

    def __init__(self, app, config=None, **kwargs):
        """Initialise the service.

        Args:
            app: The Flask application instance.
            config: Optional explicit config object. Defaults to
                `app.config`.
            **kwargs: Forwarded to `Service`.
        """
        cfg = config if config is not None else app.config
        super().__init__(config=cfg, **kwargs)
        self.config = cfg
        self.logger = app.logger

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _identifier_filter(old_username: str) -> dsl.query.Query:
        """Build the shared identifier filter for records and drafts.

        The OpenSearch filter is intentionally broad enough to use the
        indexed identifier value only. `_scan_ids` then uses the full source
        metadata from each scan hit to keep only entries where the matching
        identifier also has `scheme == "kc_username"`.

        Args:
            old_username: The pre-rename KC username to search for.

        Returns:
            A query DSL object matching creator or contributor identifiers.
        """
        creators_field = "metadata.creators.person_or_org.identifiers.identifier"
        contributors_field = (
            "metadata.contributors.person_or_org.identifiers.identifier"
        )
        return dsl.Q(
            "bool",
            should=[
                dsl.Q("term", **{creators_field: old_username}),
                dsl.Q("term", **{contributors_field: old_username}),
            ],
            minimum_should_match=1,
        )

    @staticmethod
    def _has_kc_username(source: dict[str, Any], username: str) -> bool:
        """Check source metadata for a matching KC username identifier.

        Args:
            source: The full record source returned by the scan hit.
            username: The username to match.

        Returns:
            `True` if a creator or contributor has a matching
            `kc_username` identifier.
        """
        metadata = source.get("metadata") or {}
        return any(
            [
                identifier.get("scheme") == "kc_username"
                and identifier.get("identifier") == username
                for field in ("creators", "contributors")
                for entry in metadata.get(field) or []
                for identifier in (
                    entry.get("person_or_org") or {}
                ).get("identifiers")
                or []
            ]
        )

    def _scan_ids(
        self,
        identity: Identity,
        old_username: str,
        *,
        drafts: bool,
    ) -> Iterator[str]:
        """Scan record or draft IDs with matching KC username metadata.

        The public RDM service exposes `scan()` for published records but
        only `search_drafts()` for drafts. This method uses the same
        service `_search` path for both, swapping only the action,
        record class, search config, and read permission action.

        Args:
            identity: The Invenio identity for the scan.
            old_username: The pre-rename KC username.
            drafts: If `True`, scan drafts; otherwise scan published records.

        Yields:
            Record IDs whose full source metadata contains the old
            `kc_username` in creators or contributors.
        """
        svc = current_rdm_records_service
        action = "search_drafts" if drafts else "scan"
        record_cls = svc.draft_cls if drafts else svc.record_cls
        search_opts = svc.config.search_drafts if drafts else svc.config.search
        permission_action = "read_draft" if drafts else "read"

        search = svc._search(
            action,
            identity,
            params={},
            search_preference=None,
            record_cls=record_cls,
            search_opts=search_opts,
            extra_filter=self._identifier_filter(old_username),
            permission_action=permission_action,
        )

        for hit in search.scan():
            source = hit.to_dict()
            if self._has_kc_username(source, old_username):
                yield source["id"]

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    def rewrite(
        self,
        old_username: str,
        new_username: str,
        *,
        drafts: bool = False,
        identity: Identity | None = None,
    ) -> dict[str, int]:
        """Rewrite the kc_username identifier across records or drafts.

        Default (`drafts=False`) operates on the published-records
        index: each match is opened via `edit()`, patched with
        `update_draft()`, and re-published. With `drafts=True`, draft
        hits are scanned through the same service search path with the
        draft search configuration, opened via `read_draft()`, and
        patched with `update_draft()`; drafts are never auto-published.

        The scan filters by identifier value first, then checks the full
        hit metadata for `scheme == "kc_username"` before returning a
        record ID. That prevents false positives from reaching `edit()`.

        Per-record errors are caught and counted under `failed` but
        never raised, mirroring
        `NamesSyncService.backfill_cited_orcid_from_records`.

        Args:
            old_username: The pre-rename KC username.
            new_username: The post-rename KC username.
            drafts: If `True`, operate on the drafts index; otherwise
                operate on the published-records index.
            identity: Optional Invenio identity. Defaults to
                `system_identity`.

        Returns:
            Stats dict with keys `matched`, `updated`, `failed`, and one
            of `drafts_left_uncommitted` (published pass) or `no_op`
            (drafts pass) depending on `drafts`.
        """
        identity = identity or system_identity
        phase = "drafts" if drafts else "published"
        no_change_key = "no_op" if drafts else "drafts_left_uncommitted"
        stats: dict[str, int] = {
            "matched": 0,
            "updated": 0,
            "failed": 0,
            no_change_key: 0,
        }

        if not old_username or not new_username or old_username == new_username:
            return stats

        try:
            record_ids = list(
                self._scan_ids(identity, old_username, drafts=drafts)
            )
        except Exception:  # noqa: BLE001 - logged, never propagated
            self.logger.exception(
                "rewrite[%s]: scan for old kc_username=%s failed; "
                "skipping pass",
                phase,
                old_username,
            )
            return stats

        open_record = (
            current_rdm_records_service.read_draft
            if drafts
            else current_rdm_records_service.edit
        )

        for record_id in record_ids:
            stats["matched"] += 1
            try:
                draft = open_record(identity, record_id)
                draft_data = draft.to_dict()
                metadata = draft_data.get("metadata") or {}
                changed = rewrite_kc_username(
                    metadata,
                    old_username=old_username,
                    new_username=new_username,
                )
                if not changed:
                    stats[no_change_key] += 1
                    self.logger.warning(
                        "rewrite[%s]: search matched %s but no "
                        "kc_username-scheme identifier was found to "
                        "rewrite (likely OS false positive)",
                        phase,
                        record_id,
                    )
                    continue
                draft_data["metadata"] = metadata
                current_rdm_records_service.update_draft(
                    identity, draft.id, draft_data
                )
                if not drafts:
                    current_rdm_records_service.publish(identity, draft.id)
                stats["updated"] += 1
            except Exception:  # noqa: BLE001 - logged, never propagated
                stats["failed"] += 1
                self.logger.exception(
                    "rewrite[%s]: failed to rewrite kc_username on %s "
                    "(old=%s, new=%s)",
                    phase,
                    record_id,
                    old_username,
                    new_username,
                )
        return stats

    def rewrite_all(
        self,
        old_username: str,
        new_username: str,
        *,
        identity: Identity | None = None,
    ) -> dict[str, Any]:
        """Run both passes (published, then drafts) and merge stats.

        Each pass is wrapped in its own try/except so a failure in one
        phase doesn't skip the other.

        Args:
            old_username: The pre-rename KC username.
            new_username: The post-rename KC username.
            identity: Optional Invenio identity. Defaults to
                `system_identity`.

        Returns:
            Stats dict with keys `published` and `drafts`, each mapping
            to the per-pass stats dict; plus a flat `errors` count of
            top-level pass failures (distinct from per-record failures,
            which are tallied inside the per-pass stats).
        """
        identity = identity or system_identity
        result: dict[str, Any] = {
            "published": {
                "matched": 0,
                "updated": 0,
                "failed": 0,
                "drafts_left_uncommitted": 0,
            },
            "drafts": {
                "matched": 0,
                "updated": 0,
                "failed": 0,
                "no_op": 0,
            },
            "errors": 0,
        }
        for drafts in (False, True):
            phase = "drafts" if drafts else "published"
            try:
                result[phase] = self.rewrite(
                    old_username,
                    new_username,
                    drafts=drafts,
                    identity=identity,
                )
            except Exception:  # noqa: BLE001 - logged, never propagated
                result["errors"] += 1
                self.logger.exception(
                    "rewrite_all: %s-pass raised for (old=%s, new=%s)",
                    phase,
                    old_username,
                    new_username,
                )
        return result
