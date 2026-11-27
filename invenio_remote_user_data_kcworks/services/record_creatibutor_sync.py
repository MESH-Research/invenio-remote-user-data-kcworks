# Copyright (C) 2024-2026 MESH Research
#
# Invenio-Remote-User-Data-KCWorks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Service for rewriting creatibutor metadata on RDM records.

Owns two related creatibutor updates on published records and drafts:

- KC username rename: after a Profiles `updated` webhook flips a user's
  `kc_username`, rewrite matching `identifiers` entries shaped
  `{"scheme": "kc_username", "identifier": "<username>"}` so search /
  display / mention paths keep resolving.
- Display-name backfill: set matching personal creatibutors'
  `person_or_org.name` to each user's persisted profile `display_name`
  (matched by `kc_username` / `orcid` / `email`).

Why a dedicated service rather than a bare function:

- Published records: `edit() -> update_draft() -> publish()` per match,
  iterated via `scan()` for unbounded result sets. Each `publish()` cycles
  the record through indexers and any publish-time hooks (DataCite,
  remote-API provisioner, stats); that's the same path a manual edit
  would take, so it is intentional.
- Drafts: scanned on the `rdmrecords-drafts` OpenSearch alias, then
  patched with `update_draft` (no publish — drafts stay drafts; their
  owner may publish later).
- Per-record errors are caught, counted, and logged. One bad record
  must never strand the rest of the corpus, mirroring how
  `NamesSyncService.backfill_cited_orcid_from_records` and
  `CitedNamesUpsertComponent` swallow per-item failures.

Pure metadata transforms live in `utils.record_metadata`
(`rewrite_kc_username`, `rewrite_creatibutor_display_names`) so they can
be unit-tested without I/O.
"""

from __future__ import annotations

from collections.abc import Iterator
from copy import deepcopy
from typing import Any

from flask_principal import Identity
from invenio_access.permissions import system_identity
from invenio_accounts.models import User
from invenio_accounts.proxies import current_accounts
from invenio_rdm_records.proxies import current_rdm_records_service
from invenio_records_resources.services import Service
from invenio_search.engine import dsl
from invenio_search.proxies import current_search_client
from invenio_search.utils import prefix_index

from ..utils.record_metadata import (
    rewrite_creatibutor_display_names,
    rewrite_kc_username,
    user_identifier_pairs,
)

__all__ = ("RecordCreatibutorSyncService",)


class RecordCreatibutorSyncService(Service):
    """Rewrite creatibutor identifiers and names on published records and drafts.

    Construct once at app init via `InvenioRemoteUserData` and access elsewhere
    via the `current_record_creatibutor_sync_service` proxy.
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
    def _creator_kc_usernames(record_data: dict[str, Any]) -> list[str]:
        """Return kc_username identifier values on creators[0], if present.

        Args:
            record_data: Service dump/input dict with a `metadata` key.

        Returns:
            List of `kc_username` identifier strings on the first creator.
        """
        try:
            identifiers = record_data["metadata"]["creators"][0]["person_or_org"][
                "identifiers"
            ]
        except (KeyError, IndexError, TypeError):
            return []
        return [
            ident["identifier"]
            for ident in identifiers
            if isinstance(ident, dict) and ident.get("scheme") == "kc_username"
        ]

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
        return any([
            identifier.get("scheme") == "kc_username"
            and identifier.get("identifier") == username
            for field in ("creators", "contributors")
            for entry in metadata.get(field) or []
            for identifier in (entry.get("person_or_org") or {}).get("identifiers")
            or []
        ])

    def _scan_ids(
        self,
        old_username: str,
        *,
        drafts: bool,
    ) -> Iterator[str]:
        """Scan record or draft IDs with matching KC username metadata.

        Queries OpenSearch directly on `rdmrecords-records` or
        `rdmrecords-drafts` (per `drafts`) with an identifier filter, then
        yields IDs whose full source metadata has a `kc_username` scheme
        equal to `old_username`.

        Args:
            old_username: The pre-rename KC username.
            drafts: If `True`, scan `rdmrecords-drafts`; otherwise scan
                `rdmrecords-records`.

        Yields:
            Record IDs whose full source metadata contains the old
            `kc_username` in creators or contributors.
        """
        phase = "drafts" if drafts else "published"
        index_alias = (
            prefix_index("rdmrecords-drafts")
            if drafts
            else prefix_index("rdmrecords-records")
        )
        try:
            current_search_client.indices.refresh(index=index_alias)
        except Exception:  # noqa: BLE001 - best-effort; scan still runs
            self.logger.warning(
                "rewrite[%s]: index refresh failed for %s; scanning anyway",
                phase,
                index_alias,
                exc_info=True,
            )

        search = dsl.Search(
            using=current_search_client, index=index_alias
        ).filter(self._identifier_filter(old_username))

        raw_hits = 0
        matched = 0
        for hit in search.scan():
            raw_hits += 1
            source = hit.to_dict()
            if self._has_kc_username(source, old_username):
                matched += 1
                yield source["id"]
        self.logger.info(
            "rewrite[%s]: scan old=%s index=%s raw_hits=%s matched=%s",
            phase,
            old_username,
            index_alias,
            raw_hits,
            matched,
        )
    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    def find_record_ids_for_kc_username(
        self,
        old_username: str,
    ) -> dict[str, list[str]]:
        """List record IDs whose metadata cites `old_username` as kc_username.

        Scans published records and drafts separately, using the same
        OpenSearch filter and post-filter as `rewrite()`.

        NOTE:
            Currently only used for the CLI dry-run count of records that
            would be affected.

        Args:
            old_username: The KC username to match in creator/contributor
                `kc_username` identifiers.

        Returns:
            Dict with `published` and `drafts` keys, each a list of record
            UUID strings. Empty lists when `old_username` is blank or when
            a scan phase fails.
        """
        result: dict[str, list[str]] = {"published": [], "drafts": []}
        if not old_username:
            return result
        for drafts, phase in ((False, "published"), (True, "drafts")):
            try:
                result[phase] = list(
                    self._scan_ids(old_username, drafts=drafts)
                )
            except Exception:  # noqa: BLE001 - logged, never propagated
                self.logger.exception(
                    "find_record_ids_for_kc_username: %s scan for "
                    "old kc_username=%s failed",
                    phase,
                    old_username,
                )
        return result

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
        `update_draft()`, and re-published. With `drafts=True`, only
        unpublished drafts are scanned (see `_scan_ids`), opened via
        `read_draft()`, and patched with `update_draft()`; drafts are
        never auto-published.

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
            record_ids = list(self._scan_ids(old_username, drafts=drafts))
        except Exception:  # noqa: BLE001 - logged, never propagated
            self.logger.exception(
                "rewrite[%s]: scan for old kc_username=%s failed; skipping pass",
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
                # Prefer .data (input shape) over to_dict() dump (links/expansions).
                draft_data = deepcopy(draft.data)
                before_revision = draft_data.get("revision_id")
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
                updated = current_rdm_records_service.update_draft(
                    identity, draft.id, draft_data
                )
                after_update_revision = (
                    updated.data.get("revision_id") if updated is not None else None
                )
                # Fresh read_draft: is this revision visible in the same session?
                try:
                    reread_draft = current_rdm_records_service.read_draft(
                        identity, draft.id
                    )
                    reread_data = reread_draft.data
                    self.logger.info(
                        "rewrite[%s]: post-update_draft reread id=%s "
                        "revision_id=%s (update returned %s) kc_usernames=%s",
                        phase,
                        draft.id,
                        reread_data.get("revision_id"),
                        after_update_revision,
                        self._creator_kc_usernames(reread_data),
                    )
                except Exception:  # noqa: BLE001 - diagnostic only
                    self.logger.exception(
                        "rewrite[%s]: post-update_draft reread failed id=%s "
                        "(update returned revision_id=%s)",
                        phase,
                        draft.id,
                        after_update_revision,
                    )
                after_publish_revision = None
                if not drafts:
                    published = current_rdm_records_service.publish(
                        identity, draft.id
                    )
                    after_publish_revision = (
                        published.data.get("revision_id")
                        if published is not None
                        else None
                    )
                    try:
                        reread_pub = current_rdm_records_service.read(
                            identity, record_id
                        )
                        self.logger.info(
                            "rewrite[%s]: post-publish reread id=%s "
                            "revision_id=%s (publish returned %s) "
                            "kc_usernames=%s",
                            phase,
                            record_id,
                            reread_pub.data.get("revision_id"),
                            after_publish_revision,
                            self._creator_kc_usernames(reread_pub.data),
                        )
                    except Exception:  # noqa: BLE001 - diagnostic only
                        self.logger.exception(
                            "rewrite[%s]: post-publish reread failed id=%s "
                            "(publish returned revision_id=%s)",
                            phase,
                            record_id,
                            after_publish_revision,
                        )
                self.logger.info(
                    "rewrite[%s]: wrote id=%s old=%s new=%s "
                    "revision_id before=%s after_update=%s after_publish=%s",
                    phase,
                    record_id,
                    old_username,
                    new_username,
                    before_revision,
                    after_update_revision,
                    after_publish_revision,
                )
                stats["updated"] += 1
            except Exception:  # noqa: BLE001 - logged, never propagated
                stats["failed"] += 1
                self.logger.exception(
                    "rewrite[%s]: failed to rewrite kc_username on %s (old=%s, new=%s)",
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

    # ------------------------------------------------------------------
    # Creatibutor display_name rewrite (same edit/publish shell)
    # ------------------------------------------------------------------

    def _scan_ids_for_identifier_value(
        self,
        identifier: str,
        *,
        drafts: bool,
    ) -> Iterator[str]:
        """Yield record IDs whose creatibutors cite `identifier` (any scheme).

        Unlike `_scan_ids`, this does not post-filter on `kc_username` scheme;
        callers that rewrite by profile identifier pairs apply scheme checks
        in `rewrite_creatibutor_display_names`.

        Args:
            identifier: Creatibutor identifier value to match.
            drafts: If `True`, scan drafts; otherwise published records.

        Yields:
            Record ID strings.
        """
        index_alias = (
            prefix_index("rdmrecords-drafts")
            if drafts
            else prefix_index("rdmrecords-records")
        )
        search = (
            dsl.Search(using=current_search_client, index=index_alias)
            .filter(self._identifier_filter(identifier))
            .source(["id"])
        )
        for hit in search.scan():
            source = hit.to_dict() if hasattr(hit, "to_dict") else dict(hit)
            record_id = source.get("id") or getattr(hit, "meta", {}).get("id")
            if record_id:
                yield str(record_id)

    def _apply_creatibutor_display_name(
        self,
        record_id: str,
        *,
        display_name: str,
        id_pairs: list[tuple[str, str]],
        drafts: bool,
        dry_run: bool,
        identity: Identity,
    ) -> str:
        """Rewrite one record/draft. Returns `updated`, `unchanged`, or `failed`."""
        try:
            if dry_run:
                # Read only — never `edit()`, which would leave an open draft.
                record = (
                    current_rdm_records_service.read_draft(identity, record_id)
                    if drafts
                    else current_rdm_records_service.read(identity, record_id)
                )
                metadata = deepcopy(record.data.get("metadata") or {})
                changed = rewrite_creatibutor_display_names(
                    metadata,
                    display_name=display_name,
                    id_pairs=id_pairs,
                )
                return "updated" if changed else "unchanged"

            if drafts:
                draft = current_rdm_records_service.read_draft(identity, record_id)
            else:
                draft = current_rdm_records_service.edit(identity, record_id)
            draft_data = deepcopy(draft.data)
            metadata = draft_data.get("metadata") or {}
            changed = rewrite_creatibutor_display_names(
                metadata,
                display_name=display_name,
                id_pairs=id_pairs,
            )
            if not changed:
                return "unchanged"
            draft_data["metadata"] = metadata
            current_rdm_records_service.update_draft(identity, draft.id, draft_data)
            if not drafts:
                current_rdm_records_service.publish(identity, draft.id)
            return "updated"
        except Exception:  # noqa: BLE001 - counted by caller
            self.logger.exception(
                "creatibutor display_name rewrite failed for record %s (drafts=%s)",
                record_id,
                drafts,
            )
            return "failed"

    def backfill_creatibutor_display_names(
        self,
        *,
        dry_run: bool = False,
        limit: int | None = None,
        user_id: int | str | None = None,
        identity: Identity | None = None,
    ) -> dict[str, int]:
        """Rewrite creatibutor `name` to each user's persisted `display_name`.

        Matches personal creators/contributors by profile identifiers
        (`kc_username`, `orcid`, `email`) only. Skips users without
        `display_name` or without identifiers. Uses the same
        edit/update_draft/publish shell as username rewrites.

        Args:
            dry_run: Count would-be updates without writing.
            limit: Stop after this many record updates (published + drafts).
            user_id: When set, only process this local user.
            identity: Optional Invenio identity. Defaults to `system_identity`.

        Returns:
            Stats: `users_scanned`, `users_eligible`, `records_updated`,
            `records_unchanged`, `records_failed`, `errors`.
        """
        identity = identity or system_identity
        stats = {
            "users_scanned": 0,
            "users_eligible": 0,
            "records_updated": 0,
            "records_unchanged": 0,
            "records_failed": 0,
            "errors": 0,
        }

        if user_id is not None:
            user = current_accounts.datastore.get_user_by_id(user_id)
            if user is None:
                stats["errors"] += 1
                self.logger.error(
                    "creatibutor display_name backfill: user %s not found", user_id
                )
                return stats
            users: Iterator[User] = iter([user])
        else:
            users = User.query.order_by(User.id).yield_per(200)

        for user in users:
            stats["users_scanned"] += 1
            try:
                profile = dict(user.user_profile or {})
                display_name = (profile.get("display_name") or "").strip()
                id_pairs = user_identifier_pairs(profile)
                if not display_name or not id_pairs:
                    continue
                stats["users_eligible"] += 1

                seen: set[str] = set()
                for _scheme, identifier in id_pairs:
                    for drafts in (False, True):
                        try:
                            record_ids = list(
                                self._scan_ids_for_identifier_value(
                                    identifier, drafts=drafts
                                )
                            )
                        except Exception:  # noqa: BLE001 - logged, continue
                            stats["errors"] += 1
                            self.logger.exception(
                                "creatibutor display_name backfill: scan failed "
                                "for user=%s identifier=%s drafts=%s",
                                user.id,
                                identifier,
                                drafts,
                            )
                            continue

                        for record_id in record_ids:
                            key = f"{'d' if drafts else 'p'}:{record_id}"
                            if key in seen:
                                continue
                            seen.add(key)

                            if (
                                limit is not None
                                and stats["records_updated"] >= limit
                            ):
                                return stats

                            result = self._apply_creatibutor_display_name(
                                record_id,
                                display_name=display_name,
                                id_pairs=id_pairs,
                                drafts=drafts,
                                dry_run=dry_run,
                                identity=identity,
                            )
                            if result == "updated":
                                stats["records_updated"] += 1
                            elif result == "unchanged":
                                stats["records_unchanged"] += 1
                            else:
                                stats["records_failed"] += 1
            except Exception:  # noqa: BLE001 - counted, not propagated
                stats["errors"] += 1
                self.logger.exception(
                    "creatibutor display_name backfill: user %s failed", user.id
                )

        return stats
