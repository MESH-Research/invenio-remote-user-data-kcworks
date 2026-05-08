# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Names vocabulary synchronization for KCWorks.

Mirrors KCWorks users into the `names` vocabulary for lookup on, e.g.,
the deposit form. Also handles insertion and refresh of `kcworks-cited`
records sourced from ORCID, as well as merging of data from ORCID
records into local user information when a local-user record relates
to an ORCID-keyed record that was inserted as a cited stub from ORCID
because, e.g., an ORCID-identified contributor was cited in a deposit
draft.

The `NamesSyncService`, is instantiated once by the extension's
`init_services` and exposed via the `current_names_sync_service` proxy.

Key design points
-----------------

* Every local KCWorks user that has a `identifier_kc_username` in
  their `user_profile` gets exactly one Names record whose PID is
  the bare KC username. The `kcworks-user` tag is what discriminates
  these Names records from records created by other sources. The
  record carries both the KC username and the ORCID iD (when known)
  in its `identifiers` list so that the Names service
  `resolve(value, scheme)` lookup works for either ORCID or KC
  username.
* When a draft is saved with an ORCID-identified contributor that is
  not already in the Names vocabulary, a Names record is created with
  the ORCID iD as its PID and tagged `kcworks-cited`. Insertion (and
  later refresh) is delegated to
  `NamesSyncService.upsert_cited_orcid_name()`, which is wired up by
  the ORCID client and the RDM record service component. Existing
  `kcworks-user` records carrying the same ORCID are never overwritten
  by this path.
* When a cited person later becomes a KCWorks user with the same
  ORCID, `NamesSyncService.merge_cited_orcid_into_kc()` folds the
  ORCID record into the KC-user record (merging identifiers and
  affiliations, filling in missing names and props) and then deletes
  the cited Names record. This dedup path runs both as a side effect
  of `NamesSyncService.upsert_name_for_user()` and as part of the
  periodic `KCWorksNamesSyncJob` deduplication sweep.

All operations on the service operate with `system_identity` by
default; callers that already hold an identity should pass it
explicitly.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Mapping
from datetime import UTC, datetime
from itertools import combinations
from typing import Any, Literal, cast

import jellyfish
from flask_principal import Identity
from invenio_access.permissions import system_identity
from invenio_accounts.models import User
from invenio_pidstore.errors import PIDAlreadyExists, PIDDoesNotExistError
from invenio_rdm_records.proxies import current_rdm_records_service
from invenio_records_resources.proxies import current_service_registry
from invenio_records_resources.services import Service
from invenio_search.engine import dsl
from sqlalchemy.exc import NoResultFound

from ..config import KCNamesTag
from ..types.names import (
    NameAffiliationDict,
    NameIdentifierDict,
    NamePropsDict,
    NamesRecordDict,
)
from ..utils.dicts import merge_dicts_first_wins, union_dicts_by_key
from ..utils.names import (
    get_family_name,
    get_full_name_inverted,
    get_given_name,
)
from ..utils.orcid_payload import collect_orcid_payloads
from .name_similarity import PersonNameComparator

__all__ = ("NamesSyncService",)


GIVEN_NAME_SIMILARITY_THRESHOLD = 0.70
"""
Minimum `PersonNameComparator.compare(...).score` for a within-bucket pair to
be surfaced as a likely-duplicate candidate. The score scale is
recall-oriented (default `coverage_weight=0.7`), so a threshold of 0.70
admits cases like ("Mary", "Pauline Mary") = 0.85 while still rejecting
unrelated tokens. False positives are preferred over false negatives
because the report is a human-review queue.
"""

GIVEN_NAME_WORD_FUZZY_THRESHOLD = 0.80
"""
Per-token fuzzy threshold inside `PersonNameComparator._compatible`:
two tokens are considered compatible if `SequenceMatcher.ratio()` meets
this bar (in addition to the equivalence-table and initial-prefix rules).
"""

GIVEN_NAME_COVERAGE_WEIGHT = 0.70
"""
Weight assigned to coverage-of-shorter-name vs completeness-of-longer-name
in the `PersonNameComparator` score formula:
  score = coverage_weight * (matched / min) + (1 - coverage_weight) * (matched / max)
"""

PARTIAL_FAMILY_DISCOUNT = 0.90
"""
Multiplier applied to a candidate-pair score when the family-name similarity is
only partial: i.e. the records share at least one *piece* of their family
name (e.g. just `garcia` from `García López` vs `García-Smith`) rather than
the full canonical form. Higher = more recall on multi-part family-name
variants; lower = stricter ranking advantage to full-family matches.
"""

PHONETIC_FAMILY_DISCOUNT = 0.85
"""
Multiplier applied when the family-name similarity is phonetic
(records share a Metaphone code rather than an exact normalized
family token). Set so a perfect given-name match (1.0)
still clears `GIVEN_NAME_SIMILARITY_THRESHOLD` after discount.
"""

EMPTY_GIVEN_NAME_SCORE = 0.85
"""
Baseline score assigned to a pair when both records have an empty
`given_name`. The `PersonNameComparator` would otherwise return its
`empty_score` (0.30) and the pair would fall below threshold; we surface
such pairs anyway. Combined with `PARTIAL_FAMILY_DISCOUNT` or 
`PHONETIC_FAMILY_DISCOUNT` as appropriate.
"""

# Cache key for the incremental-dedup bookmark (ISO datestamp).
_DEDUP_BOOKMARK_KEY = "kcworks:names_sync:dedup:last_sweep"

# Per-page bucket count for the composite aggregation that powers
# `_fetch_dedup_buckets`. The composite agg pages exhaustively over the
# family-token / phonetic-code keyspaces; this is the cluster-side page
# size, not a cap on total buckets returned. Singletons are filtered
# server-side via a `bucket_selector` pipeline agg, so each page can
# return fewer buckets than this.
_DEDUP_PAGE_SIZE = 1000


def _pair_touches_recent(cand: dict[str, Any], bookmark: datetime) -> bool:
    """Return `True` if either side of `cand` was updated at or after `bookmark`.

    Used to filter `find_duplicate_candidates` candidate pairs in
    incremental-dedup mode: a pair is in scope if at least one side has
    been touched since the previous sweep. A pair where neither side
    has been touched cannot have any new information to surface and is
    safely skipped.

    Each side's `updated` timestamp is read from the indexed doc
    (`hit['_source']['updated']`, propagated through
    `_fetch_dedup_buckets`'s `top_hits`). A record missing the
    timestamp is treated as recent so that records pre-dating the
    field, or test fixtures that omit it, are never silently dropped
    from a sweep.

    Args:
        cand: A candidate-pair dict from the dedup pipeline. Must
            carry `record_a` and `record_b` keys whose values are
            indexed-doc-shaped dicts.
        bookmark: The cutoff timestamp. Pairs with both sides strictly
            older than this are excluded. Naive datetimes are treated
            as UTC for the comparison.

    Returns:
        `True` if at least one side is recent enough to keep the pair
        in scope; `False` if both sides are strictly older than the
        bookmark.
    """
    if bookmark.tzinfo is None:
        bookmark = bookmark.replace(tzinfo=UTC)
    for rec in (cand["record_a"], cand["record_b"]):
        updated_iso = rec.get("updated")
        if not updated_iso:
            return True
        try:
            updated_at = datetime.fromisoformat(str(updated_iso))
        except ValueError:
            return True
        if updated_at.tzinfo is None:
            updated_at = updated_at.replace(tzinfo=UTC)
        if updated_at >= bookmark:
            return True
    return False


class NamesSyncService(Service):
    """Orchestrates KCWorks-specific upkeep of the Names vocabulary.

    Construct once at app init via `InvenioRemoteUserData` and access elsewhere via the
    `current_names_sync_service` proxy.

    The primary public method to be used by callers is `upsert_name_for_user`.
    """

    def __init__(self, app, config=None, **kwargs):
        """Initialise the service.

        Notes:
            The Flask app config is passed through as the service `config`
            so that lookups like `self.config.get("REMOTE_USER_DATA_NAMES_*")`
            resolve against the live application config.

        Args:
            app: The Flask application instance.
            config: Optional explicit config object. Defaults to
                `app.config`. Tests pass a dict here.
            **kwargs: Forwarded to `Service`.
        """
        cfg = config if config is not None else app.config
        super().__init__(config=cfg, **kwargs)
        self.config = cfg
        self.logger = app.logger
        self._top_hits_per_dedup_bucket = cfg.get(
            "REMOTE_USER_DATA_NAMES_DEDUP_TOP_HITS_PER_BUCKET", 2000
        )
        self._given_name_comparator = PersonNameComparator(
            word_fuzzy_threshold=GIVEN_NAME_WORD_FUZZY_THRESHOLD,
            coverage_weight=GIVEN_NAME_COVERAGE_WEIGHT,
        )

    @property
    def names_service(self):
        """Return the upstream Names vocabulary service.

        Looked up on every access so the binding survives test
        teardown / re-registration cycles.
        """
        return current_service_registry.get("names")

    @staticmethod
    def _format_name_parts(
        profile: dict,
    ) -> tuple[str | None, str | None, str | None, dict[str, str]]:
        """Extract names and the structured parts from a profile.

        `name_parts_local` (the user's local override) wins over
        `name_parts` (the remote-synced value) so manually corrected
        splits survive remote re-syncs. Both are stored as JSON
        strings in the user_profile blob; we parse to a real dict
        here.

        Composes `given_name`, `family_name`, and the inverted
        display form via the shared `utils.names` helpers, which
        handle particles, suffixes, and multi-part given names. The
        returned `name_inverted` is the rich inverted form when parts are
        available; otherwise the profile's `full_name`.

        Args:
            profile: The user's `user_profile` dict.

        Returns:
            A four-tuple `(name_inverted, given_name, family_name, parts)`.
            `name_inverted`, `given_name`, and `family_name` may each be
            `None`; `parts` is `{}` when no structured parts are
            available.
        """
        raw_parts = profile.get("name_parts_local") or profile.get("name_parts")
        parts: dict[str, str] = {}
        if raw_parts:
            try:
                parsed = (
                    raw_parts if isinstance(raw_parts, dict) else json.loads(raw_parts)
                )
                if isinstance(parsed, dict):
                    parts = {k: v for k, v in parsed.items() if isinstance(v, str)}
            except (TypeError, ValueError, json.JSONDecodeError):
                parts = {}

        given = get_given_name(parts) or None if parts else None
        family = get_family_name(parts) or None if parts else None

        name_inverted = (
            (get_full_name_inverted(parts) if parts else None)
            or profile.get("full_name")
            or None
        )

        return name_inverted, given, family, parts

    @staticmethod
    def _build_identifiers(profile: dict) -> list[NameIdentifierDict]:
        """Build a Names `identifiers` list from a user profile dict.

        Mirrors both the KC username (`kc_username` scheme) and the
        user's ORCID iD (`orcid` scheme) when present (registered in
        VOCABULARIES_NAMES_SCHEMES in invenio.cfg).

        Storing `kc_username` in `identifiers` (in addition to it
        being the PID) lets `NamesService.resolve(kc_username, "kc_username")`
        answer scheme-based lookups symmetrically with ORCID.

        Args:
            profile: The user's `user_profile` dict.

        Returns:
            A list of `{"scheme": ..., "identifier": ...}` dicts,
            possibly empty.
        """
        identifiers: list[NameIdentifierDict] = []
        kc_username = profile.get("identifier_kc_username") or ""
        if kc_username:
            identifiers.append({"scheme": "kc_username", "identifier": kc_username})
        orcid = profile.get("identifier_orcid") or ""
        if orcid:
            identifiers.append({"scheme": "orcid", "identifier": orcid})
        return identifiers

    @staticmethod
    def _build_affiliations(profile: dict) -> list[NameAffiliationDict]:
        """Build a Names `affiliations` list from a user profile dict.

        Profiles store the affiliation as a single free-text string. We
        map it to a single un-resolved affiliation entry. The Names
        vocabulary treats this as a free-text affiliation when no
        `id` is supplied.

        Args:
            profile: The user's `user_profile` dict.

        Returns:
            A list with at most one `{"name": ...}` entry, or empty
            when the profile has no affiliation string.
        """
        raw = profile.get("affiliations")
        if not raw or not isinstance(raw, str):
            return []
        return [{"name": raw}]

    _FAMILY_TOKEN_PUNCT_RE = re.compile(r"[^\w\s]", re.UNICODE)
    # Same as `_FAMILY_TOKEN_PUNCT_RE` but preserves hyphens so they can act
    # as a separator (along with whitespace) in `_compute_family_dedup_tokens`.
    _FAMILY_PART_TOKEN_PUNCT_RE = re.compile(r"[^\w\s\-]", re.UNICODE)
    _FAMILY_PART_TOKEN_SPLIT_RE = re.compile(r"[\s\-]+", re.UNICODE)

    @classmethod
    def _normalize_family_token(cls, family: str | None) -> str:
        """Normalize a `family_name` into a coarse dedup bucket key.

        NFKD-asciifolds, lowercases, strips punctuation (apostrophes,
        hyphens, etc.), and collapses internal whitespace so that
        spelling variants share a bucket: `O'Brien`/`OBrien`,
        `Müller`/`Mueller`, `de la Torre`/`De La Torre`. The resulting
        string is stored as `props.family_token` and used as the
        agg bucket key in `find_duplicate_candidates`.

        Args:
            family: A raw `family_name` string, possibly `None`.

        Returns:
            The normalized token, or the empty string when `family`
            is empty or `None`. Callers should omit `family_token`
            from `props` when the result is empty.
        """
        if not family:
            return ""
        folded = (
            unicodedata
            .normalize("NFKD", family)
            .encode("ascii", "ignore")
            .decode("ascii")
        )
        cleaned = cls._FAMILY_TOKEN_PUNCT_RE.sub("", folded).lower()
        return " ".join(cleaned.split())

    @classmethod
    def _compute_family_dedup_tokens(
        cls, family: str | None
    ) -> tuple[list[str], list[str]]:
        """Compute both family-name dedup-bucket indexes in one pass.

        Returns `(part_tokens, phonetic_tokens)`. Both lists derive
        from the same NFKD-folded, lowercased, punctuation-stripped,
        whitespace-and-hyphen-split pieces of `family`, so we
        tokenize once and produce both outputs together. Callers
        always need both (the payload builders set
        `props.family_part_tokens` and `props.family_phonetic_tokens`
        as a pair).

        `part_tokens`
            The full normalized form followed by each constituent
            piece, deduped while preserving order. Hyphens act as
            separators (unlike `_normalize_family_token`, which
            strips them and concatenates the surrounding pieces).
            Stored as `props.family_part_tokens` and used as the
            multi-valued aggregation key in the token pass of
            `find_duplicate_candidates`, so records with multi-part
            or hyphenated family names cluster both with each other
            and with single-part records sharing any one piece
            (e.g. `García López`, `García-López`, and `García` all
            surface in the `garcia` bucket). Element 0 is always the
            full canonical form when non-empty;
            `_score_bucket_pairs` relies on this to classify hits as
            full-family vs partial-family.

        `phonetic_tokens`
            Each piece encoded with Metaphone, deduped,
            order-preserving. Empty codes (e.g. from single-letter
            pieces the encoder cannot reduce) are filtered out.
            Stored as `props.family_phonetic_tokens` and used as the
            multi-valued aggregation key in the phonetic pass.
            Catches spelling variants that survive the part-token
            normalization, e.g. `Smith`/`Smyth` (both `SM0`),
            `OBrien`/`OBrian` (both `OBRN`),
            `Schaefer`/`Schaffer` (both `SXFR`).

        Algorithm choice for the phonetic encoder: we use Metaphone
        because it collapses canonical name-spelling variants like
        `Smith`/`Smyth` that NYSIIS (the other obvious candidate,
        also exposed by `jellyfish`) preserves as distinct
        (`SNAT`/`SNYT`). NYSIIS is more discriminating for personal
        names overall and would produce fewer false positives;
        switch the `jellyfish.metaphone` call below to
        `jellyfish.nysiis` if the false-positive rate from Metaphone
        proves intolerable in practice.

        Examples:
            * `"García López"` →
              `(["garcia lopez", "garcia", "lopez"], ["KRS", "LPS"])`
            * `"García-López"` →
              `(["garcia lopez", "garcia", "lopez"], ["KRS", "LPS"])`
            * `"Smith"`        → `(["smith"], ["SM0"])`
            * `""` / `None`    → `([], [])`

        Args:
            family: A raw `family_name` string, possibly `None`.

        Returns:
            A `(part_tokens, phonetic_tokens)` tuple. Either list may
            be empty independently (a non-empty `family` whose pieces
            all encode to empty Metaphone codes yields a non-empty
            `part_tokens` and an empty `phonetic_tokens`). Callers
            should omit the corresponding `props` field when its list
            is empty.
        """
        if not family:
            return [], []
        folded = (
            unicodedata
            .normalize("NFKD", family)
            .encode("ascii", "ignore")
            .decode("ascii")
        )
        cleaned = cls._FAMILY_PART_TOKEN_PUNCT_RE.sub("", folded).lower()
        pieces = [p for p in cls._FAMILY_PART_TOKEN_SPLIT_RE.split(cleaned) if p]
        if not pieces:
            return [], []

        part_tokens = [" ".join(pieces)]
        if len(pieces) > 1:
            for piece in pieces:
                if piece not in part_tokens:
                    part_tokens.append(piece)

        phonetic_tokens: list[str] = []
        for piece in pieces:
            code = jellyfish.metaphone(piece)
            if code and code not in phonetic_tokens:
                phonetic_tokens.append(code)

        return part_tokens, phonetic_tokens

    # ------------------------------------------------------------------
    # Payload builders
    # ------------------------------------------------------------------

    def build_name_payload_from_user(self, user: User) -> NamesRecordDict | None:
        """Build a Names create/update payload for a local KCWorks user.

        The minimum requirement is a `identifier_kc_username` (so we
        can compose the PID); when `name_parts`/`full_name` are
        missing we fall back to the user's username or the local-part
        of the email so that `NameSchema.validate_names` is
        satisfied.

        The returned dict is shaped for the Names service `create`/
        `update` calls. On create the `id` field is the PID; on
        update it is ignored by the NamesService.

        `props` carries the rich inverted display form
        (`display_name`) and the structured `name_parts` dict,
        because `NameSchema` overwrites the payload's `name` field
        with a naive `"family, given"` composition.

        Args:
            user: The local Invenio `User` to mirror.

        Returns:
            A Names service payload dict, or `None` when the user is
            missing or has no `identifier_kc_username` set.
        """
        if user is None:
            return None

        profile = dict(user.user_profile or {})
        kc_username = profile.get("identifier_kc_username") or ""

        name_inverted, given, family, parts = self._format_name_parts(profile)
        # Final fallback: make sure we always satisfy
        # NameSchema.validate_names.
        if not isinstance(name_inverted, str):
            if not (given and family):
                name_inverted = (
                    (user.username or "")
                    or (user.email or "").split("@", 1)[0]
                    or kc_username
                )
            else:
                name_inverted = f"{family}, {given}"

        props: NamePropsDict = {
            "kcworks_user_id": str(user.id),
        }
        display_name = name_inverted
        if parts:
            props["name_parts"] = parts
            try:
                display_name = get_full_name_inverted(parts)
            except ValueError:
                pass
        if display_name:
            props["display_name"] = display_name
        family_token = self._normalize_family_token(family)
        if family_token:
            props["family_token"] = family_token
        part_tokens, phonetic_tokens = self._compute_family_dedup_tokens(family)
        if part_tokens:
            props["family_part_tokens"] = part_tokens
        if phonetic_tokens:
            props["family_phonetic_tokens"] = phonetic_tokens

        payload: NamesRecordDict = {
            "id": kc_username,
            "internal_id": str(user.id),
            "tags": [KCNamesTag.USER],
            "identifiers": self._build_identifiers(profile),
            "affiliations": self._build_affiliations(profile),
            "props": props,
        }
        payload["name"] = display_name
        if given:
            payload["given_name"] = given
        if family:
            payload["family_name"] = family

        return payload

    def build_name_payload_from_orcid(
        self, orcid_record: dict[str, Any]
    ) -> NamesRecordDict:
        """Build a Names create payload from an ORCID `/record` dict.

        Designed to consume the dict returned by
        `OrcidClient.fetch_record()`. Pulls the ORCID iD, the person's
        preferred name(s), and current employments (as affiliations),
        and returns a payload tagged `kcworks-cited`.

        When ORCID supplies a `credit-name` (the person's preferred
        rendered form), it is preserved in `props["display_name"]`
        so the rich form survives the `NameSchema.update_name`
        rewrite that would otherwise clobber `name` to
        `"family, given"` whenever both parts are present.

        Affiliations are extracted from `activities-summary.employments`,
        skipping any employment with a non-empty `end-date`. Org IDs
        are populated only when the disambiguation source is ROR (the
        upstream `OrcidTransformer`'s broader org-IDs mapping is not
        replicated here; we can add it if we ever need other schemes).

        Args:
            orcid_record: A parsed ORCID Public API `/{orcid}/record`
                dict.

        Returns:
            A Names payload suitable for `service.create` whose
            `id` is the bare ORCID iD (e.g. `"0000-0001-2345-6789"`).

        Raises:
            ValueError: If the record carries no usable name data
                (no `credit-name` and no `family-name`); a
                `given-names`-only record is also rejected since the
                Names schema requires at least a family name when
                `name` is composed from parts.
        """
        orcid_id = (
            orcid_record.get("orcid-identifier", {}).get("path")
            or orcid_record.get("orcid")
            or ""
        )

        person = orcid_record.get("person", {}) or {}
        name_block = person.get("name", {}) or {}
        given = (name_block.get("given-names") or {}).get("value") or None
        family = (name_block.get("family-name") or {}).get("value") or None
        credit = (name_block.get("credit-name") or {}).get("value") or None

        name = credit
        if not name and family and given:
            name = f"{family}, {given}"
        elif not name and family:
            name = family
        elif not name:
            raise ValueError("No name found in ORCID record")

        props: NamePropsDict = {}
        if credit:
            props["display_name"] = credit
        family_token = self._normalize_family_token(family)
        if family_token:
            props["family_token"] = family_token
        part_tokens, phonetic_tokens = self._compute_family_dedup_tokens(family)
        if part_tokens:
            props["family_part_tokens"] = part_tokens
        if phonetic_tokens:
            props["family_phonetic_tokens"] = phonetic_tokens
        if given and family:
            props["name_parts"] = {"first": given, "last": family}

        payload: NamesRecordDict = {
            "id": orcid_id,
            "internal_id": None,
            "tags": [KCNamesTag.CITED],
            "identifiers": (
                [{"scheme": "orcid", "identifier": orcid_id}] if orcid_id else []
            ),
            "affiliations": self._extract_orcid_affiliations(orcid_record),
            "name": name,
            "props": props,
        }
        if given:
            payload["given_name"] = given
        if family:
            payload["family_name"] = family
        return payload

    def _extract_orcid_affiliations(
        self, orcid_record: dict[str, Any]
    ) -> list[NameAffiliationDict]:
        """Extract current-employment affiliations from an ORCID record.

        Mirrors `invenio_vocabularies.contrib.names.datastreams
        .OrcidTransformer._extract_affiliations` but limited to ROR
        for org-ID resolution (the upstream config-driven mapping
        for other schemes is not replicated). Skips any employment
        with a non-empty `end-date`.

        Args:
            orcid_record: A parsed ORCID Public API `/{orcid}/record`
                dict.

        Returns:
            A list of `NameAffiliationDict` entries (possibly empty),
            deduped on `id` when present, otherwise on `name`.
        """
        out: list[NameAffiliationDict] = []
        seen_ids: set[str] = set()
        seen_names: set[str] = set()

        activities = orcid_record.get("activities-summary") or {}
        employments = activities.get("employments") or {}
        groups = employments.get("affiliation-group") or []
        # The XML-derived dict path may collapse a single child into a
        # bare dict; the JSON API normalizes to lists, but accept both.
        if isinstance(groups, dict):
            groups = [groups]

        for group in groups:
            summary = group.get("employment-summary") or {}
            if summary.get("end-date"):
                continue
            org = summary.get("organization") or {}
            org_name = org.get("name")
            if not org_name:
                continue

            aff_id = None
            dis_org = org.get("disambiguated-organization") or {}
            org_scheme = dis_org.get("disambiguation-source")
            org_id = dis_org.get("disambiguated-organization-identifier")
            if org_scheme == "ROR" and org_id:
                aff_id = org_id.rsplit("/", 1)[-1]

            if aff_id and aff_id in seen_ids:
                continue
            if not aff_id and org_name in seen_names:
                continue

            entry: NameAffiliationDict = {"name": org_name}
            if aff_id:
                entry["id"] = aff_id
                seen_ids.add(aff_id)
            else:
                seen_names.add(org_name)
            out.append(entry)

        return out

    # ------------------------------------------------------------------
    # Read helper
    # ------------------------------------------------------------------

    def _read_existing(self, identity: Identity, pid: str):
        """Read a Names record by PID, returning `None` if absent.

        Args:
            identity: The Invenio identity to use for the read.
            pid: The Names record PID (its `id`) to look up.

        Returns:
            The `RecordItem` returned by `service.read`, or
            `None` when no such PID exists.
        """
        try:
            return self.names_service.read(identity, pid)
        except (PIDDoesNotExistError, NoResultFound):
            return None

    # ------------------------------------------------------------------
    # Public service operations
    # ------------------------------------------------------------------

    def upsert_name_for_user(
        self,
        user: User,
        *,
        identity: Identity | None = None,
    ) -> dict[str, Any] | None:
        """Create or update the Names vocabulary record for a user.

        This is the single method the rest of the codebase should call
        after a local user is created or updated. It is idempotent:
        running it repeatedly on an unchanged user is a no-op apart
        from a read.

        After upserting, if the user has an ORCID iD set in
        `user_profile.identifier_orcid`, this method also looks for a
        pre-existing ORCID-id Names record (tag `kcworks-cited`) that
        matches the same ORCID and merges it into the canonical record
        via `merge_cited_orcid_into_kc()`.

        Args:
            user: The local Invenio `User` to mirror.
            identity: Optional Invenio identity to use for service
                calls. Defaults to `system_identity`.

        Returns:
            The Names record dict (`RecordItem.to_dict()`) for the
            canonical record, or `None` when `user` does not have
            enough profile data to be mirrored yet.
        """
        self.logger.debug("Starting upsert")
        if user is None:
            return None
        payload = self.build_name_payload_from_user(user)
        self.logger.debug(f"payload: {payload}")
        if payload is None:
            self.logger.debug(
                "upsert_name_for_user: user %s has no kc_username; skipping",
                user.id,
            )
            return None

        service = self.names_service
        self.logger.debug(f"service is {service}")
        identity = identity or system_identity
        pid = payload["id"]
        self.logger.debug(f"pid is {pid}")

        existing = self._read_existing(identity, pid)
        self.logger.debug(f"existing user is {existing}")
        item = None
        if existing is not None:
            item = service.update(identity, pid, payload)
            self.logger.debug(
                "upsert_name_for_user: updated Names record %s for user %s",
                pid,
                user.id,
            )
        else:
            try:
                self.logger.debug("trying create")
                item = service.create(identity, payload)
            except PIDAlreadyExists:
                # Race: another worker created the record between our
                # read and create. This service is the only writer for
                # PID=kc_username records, so any winner is also one of
                # ours and an unconditional update is safe.
                item = service.update(identity, pid, payload)
                self.logger.debug(
                    "upsert_name_for_user: updated Names record %s for "
                    "user %s after create race",
                    pid,
                    user.id,
                )
            except Exception as e:
                self.logger.debug("Error upserting entry")
                self.logger.debug(e)
            else:
                self.logger.debug(
                    "upsert_name_for_user: created Names record %s for user %s",
                    pid,
                    user.id,
                )

        # If the user has an ORCID, merge any citation-triggered Names entry
        profile = dict(user.user_profile or {})
        orcid = profile.get("identifier_orcid") or ""
        if orcid and item is not None:
            self.logger.debug("Handling orcid for name sync")
            try:
                merged = self.merge_cited_orcid_into_kc(
                    cast(NamesRecordDict, item.to_dict()), identity=identity
                )
                self.logger.debug(f"merged is {merged}")
                if merged is not None:
                    # Re-read so the returned dict reflects the merged
                    # state.
                    item = service.read(identity, pid)
            except NoResultFound:
                pass  # Just means that there was no existing record to merge
            except Exception:
                # Merging is a convenience; never let it break the
                # upsert.
                self.logger.warning(
                    "upsert_name_for_user: cited-record merge failed for %s (orcid=%s)",
                    pid,
                    orcid,
                    exc_info=True,
                )

        return item.to_dict() if item is not None else None

    def upsert_cited_orcid_name(
        self,
        payload: NamesRecordDict,
        *,
        identity: Identity | None = None,
        source: str = "creatibutor",
    ) -> dict[str, Any] | None:
        """Insert or refresh a Names record from caller-supplied ORCID data.

        Called from the RDM record service component when a draft is
        saved with an ORCID-identified contributor; the component
        assembles `payload` directly from the contributor block in
        the draft, so this method does no ORCID I/O.

        `payload["id"]` must be the bare ORCID; it is also used as
        the PID lookup key.

        Behavior:

        - If a `kcworks-user` Names record already carries this ORCID
          in its `identifiers`, hand `payload` off to
          `merge_cited_orcid_into_kc`, which gap-fills the KC-user
          record (KC values win for scalar names and `props`;
          `identifiers` and `affiliations` are unioned) and
          best-effort deletes any leftover cited stub at PID=orcid.
          This function never overwrites scalar fields a KC user has
          set on their profile.
        - Otherwise, if no record exists at PID=orcid, create a new
          `kcworks-cited` record from `payload` there.
        - Otherwise (a `kcworks-cited` record, or an untagged
          harvester-origin record from the upstream
          `OrcidTransformer`, already sits at PID=orcid), wholesale
          refresh it with `payload`.

        Args:
            payload: A `NamesRecordDict` whose `id` is the bare ORCID
                iD (canonical `0000-0000-0000-000X` form, no URL
                prefix) and whose contents are derived from the data
                already in hand at the call site. Mutated in place to
                add `props["source"]` on the CITED branches; pass a
                fresh dict if you intend to reuse it.
            identity: Optional Invenio identity. Defaults to
                `system_identity`.
            source: Free-text attribution recorded in
                `props["source"]` so we can later tell what triggered
                a `kcworks-cited` record (e.g. `"creatibutor"` for the
                deposit form path). Ignored on the USER gap-fill
                branch since `source` only describes how a cited stub
                came into being.

        Returns:
            The Names record dict (gap-filled, refreshed, or newly
            created), or `None` if `payload` carries no `id` or the
            service write fails on an existing record.
        """
        orcid = payload.get("id") or ""
        if not orcid:
            return None

        service = self.names_service
        identity = identity or system_identity

        user_record = self._find_user_record_by_orcid(orcid, identity=identity)
        if user_record is not None:
            return cast(
                "dict[str, Any] | None",
                self.merge_cited_orcid_into_kc(user_record, payload, identity=identity),
            )

        payload.setdefault("props", {})["source"] = source
        item = None
        try:
            item = service.create(identity, payload)
        except PIDAlreadyExists:
            item = service.update(identity, orcid, payload)
        return item.to_dict() if item is not None else None

    def backfill_cited_orcid_from_records(
        self,
        *,
        limit: int | None = None,
        dry_run: bool = False,
        identity: Identity | None = None,
    ) -> dict[str, int]:
        """Insert Names records for ORCIDs found in published RDM records.

        Walks all published records via the RDM record service's `scan()` and,
        for every personal-type creator/contributor carrying an ORCID iD,
        calls `upsert_cited_orcid_name(payload, source="backfill")`. The
        upstream method is itself idempotent: if a USER record already carries
        the ORCID it gap-fills it; if a CITED stub already sits at PID=orcid
        it refreshes it; otherwise it creates a fresh CITED stub.

        Intended as a one-off recovery / migration tool: the on-draft-save
        component (`CitedNamesUpsertComponent`) handles new drafts going
        forward, but pre-component published records may still have
        ORCID-bearing creators without a corresponding Names record.
        Safe to re-run.

        Args:
            limit: Maximum number of records to scan. `None` (the default)
                walks the entire published corpus.
            dry_run: When `True`, count payloads but skip every
                `upsert_cited_orcid_name` call. The returned `upserted`
                counter will be `0`; `payloads_seen` reflects what *would*
                be upserted.
            identity: Optional Invenio identity for `scan()`. Defaults to
                `system_identity`.

        Returns:
            A stats dict with keys:

            - `records_scanned`: number of published records visited.
            - `payloads_seen`: total ORCID payloads collected (after within-
              record dedup).
            - `upserted`: successful upsert calls (always `0` on dry-run).
            - `errors`: upsert calls that raised (logged, not propagated).
        """
        identity = identity or system_identity
        stats = {
            "records_scanned": 0,
            "payloads_seen": 0,
            "upserted": 0,
            "errors": 0,
        }

        scan_result = current_rdm_records_service.scan(identity)
        for hit in scan_result.hits:
            if limit is not None and stats["records_scanned"] >= limit:
                break
            stats["records_scanned"] += 1
            metadata = hit.get("metadata") or {}
            payloads = collect_orcid_payloads(metadata)
            stats["payloads_seen"] += len(payloads)
            if dry_run:
                continue
            for payload in payloads:
                try:
                    self.upsert_cited_orcid_name(
                        cast("NamesRecordDict", payload),
                        identity=identity,
                        source="backfill",
                    )
                    stats["upserted"] += 1
                except Exception:  # noqa: BLE001 - logged, never propagated
                    stats["errors"] += 1
                    # Per-record errors are logged and counted but do not
                    # abort the walk; one bad record shouldn't strand the
                    # rest of the corpus.
                    self.logger.exception(
                        "backfill_cited_orcid_from_records: "
                        "upsert_cited_orcid_name failed for ORCID %s",
                        payload.get("id"),
                    )
        return stats

    def _find_user_record_by_orcid(
        self,
        orcid: str,
        *,
        identity: Identity | None = None,
    ) -> NamesRecordDict | None:
        """Resolve `orcid` and return the USER-tagged hit, if any.

        Uses `resolve(..., many=True)` because both a USER record (at
        PID=kc_username) and a CITED record (at PID=orcid_id) may carry
        the same ORCID identifier in their `identifiers` list during a
        consolidation window. The single-result form's order is
        OpenSearch-defined and would silently pick either.

        Args:
            orcid: The bare ORCID iD (canonical
                `0000-0000-0000-000X` form).
            identity: Optional Invenio identity. Defaults to
                `system_identity`.

        Returns:
            The first hit dict tagged `kcworks-user`, or `None` if no
            USER hit is among the matches (or if there are no matches
            at all).
        """
        identity = identity or system_identity
        try:
            resolved = self.names_service.resolve(identity, orcid, "orcid", many=True)
        except PIDDoesNotExistError:
            return None
        hits = cast(
            list[NamesRecordDict],
            resolved.to_dict().get("hits", {}).get("hits", []),
        )
        return next(
            (h for h in hits if KCNamesTag.USER in h.get("tags", [])),
            None,
        )

    def merge_cited_orcid_into_kc(
        self,
        kc_record: NamesRecordDict,
        cited_data: NamesRecordDict | None = None,
        *,
        identity: Identity | None = None,
    ) -> NamesRecordDict | None:
        """Merge ORCID-derived data into a KC-user Names record.

        The KC-side merge primitive. KC values win for scalar names
        and `props`; `identifiers` and `affiliations` are unioned;
        `props["source"]` from the cited side is dropped (it describes
        only how a cited stub came into being and is meaningless on a
        KC-user record). After updating `kc_record`, attempts to
        delete any cited Names record at PID=orcid_id; a missing
        record is treated as success since callers may not have
        written a stub.

        Two callers, two ways of supplying the cited data:

        - The deposit-form path (`upsert_cited_orcid_name`) hands in
          a freshly-built payload from a draft contributor block.
        - `upsert_name_for_user` (and the planned dedup job) leaves
          `cited_data` as `None`, in which case this method reads the
          record from the database at PID=ORCID-from-`kc_record`. Any
          tag is acceptable except `kcworks-user`: cited stubs,
          untagged harvester-origin records, etc. all get folded in;
          a USER hit would mean two distinct KC-user records carry
          the same ORCID, which the dedupe sweep flags for human
          review rather than silently consolidating.

        Args:
            kc_record: The KC-user Names record dict to merge into
                (must carry `id` and an `orcid`-scheme entry in
                `identifiers`).
            cited_data: Optional pre-supplied cited-side data in
                Names-payload shape. When `None`, read from the DB at
                PID=ORCID and require the `kcworks-cited` tag.
            identity: Optional Invenio identity. Defaults to
                `system_identity`.

        Returns:
            The merged KC record dict on success, or `None` when there
            was nothing to do (no ORCID on `kc_record`, auto-merge
            disabled, no DB-resident record at PID=orcid when
            `cited_data` was omitted, the DB-resident candidate was
            itself `kcworks-user`-tagged, or the KC update failed).
        """
        if not kc_record:
            return None
        if not self.config["REMOTE_USER_DATA_NAMES_AUTO_MERGE_ON_ORCID"]:
            return None

        orcid = next(
            (
                i.get("identifier", "")
                for i in kc_record.get("identifiers", [])
                if (i.get("scheme", "").lower() == "orcid")
            ),
            "",
        )
        if not orcid:
            return None

        service = self.names_service
        identity = identity or system_identity

        if cited_data is None:
            try:
                cited = service.read(identity, orcid)
            except PIDDoesNotExistError:
                return None
            cited_data = cast(NamesRecordDict, cited.to_dict())
            # Refusing to merge a USER record into another USER record
            # carrying the same ORCID. This is a duplicate-user anomaly
            # to be flagged by the dedupe sweep for human review.
            if KCNamesTag.USER in cited_data.get("tags", []):
                return None

        merged_payload = self._merge_orcid_data_into_kc(kc_record, cited_data)

        try:
            item = service.update(identity, kc_record["id"], merged_payload)
        except Exception:
            self.logger.warning(
                "merge_cited_orcid_into_kc: failed to update kc record %s "
                "with merged ORCID data",
                kc_record.get("id"),
                exc_info=True,
            )
            return None

        # Clean up any cited stub at PID=orcid_id.
        try:
            service.delete(identity, orcid)
        except PIDDoesNotExistError:
            pass
        except Exception:
            self.logger.warning(
                "merge_cited_orcid_into_kc: kc record %s was updated but "
                "deletion of cited stub at %s failed; the next dedupe "
                "sweep will retry",
                kc_record.get("id"),
                orcid,
                exc_info=True,
            )

        self.logger.info(
            "merge_cited_orcid_into_kc: merged ORCID data for %s into %s",
            orcid,
            kc_record.get("id"),
        )
        return cast(NamesRecordDict, item.to_dict()) if item is not None else None

    @staticmethod
    def _identifier_key(ident: Mapping[str, Any]) -> tuple[str, str]:
        """Hashable dedup key for an `identifiers` entry.

        `IdentifierSchema` validates `scheme` and `identifier` as
        non-empty strings, so we can index without fallbacks.

        Returns:
            A `(scheme, value)` tuple, both lowercased for
            case-insensitive collision detection.
        """
        return (ident["scheme"].lower(), ident["identifier"].lower())

    @staticmethod
    def _affiliation_key(aff: Mapping[str, Any]) -> tuple[str, str] | None:
        """Hashable dedup key for an `affiliations` entry, or `None` to skip.

        Returns:
            A `(id, name)` tuple, both lowercased, or `None` when the
            entry has neither `id` nor `name` (in which case
            `union_dicts_by_key` skips it entirely).
        """
        aff_id = aff.get("id", "")
        aff_name = aff.get("name", "")
        if not aff_id and not aff_name:
            return None
        return (aff_id.lower(), aff_name.lower())

    def _merge_orcid_data_into_kc(
        self,
        kc_record: NamesRecordDict,
        orcid_data: NamesRecordDict,
    ) -> NamesRecordDict:
        """Build a merged update payload from a KC record and ORCID-derived data.

        Shared by `merge_cited_orcid_into_kc` (where `orcid_data` is a
        sibling `kcworks-cited` Names record dict read from the
        service) and the USER-tag branch of `upsert_cited_orcid_name`
        (where `orcid_data` is a freshly-built payload from
        `build_name_payload_from_orcid`).

        KC values win for scalar names and `props`; `identifiers` and
        `affiliations` are unioned. The KC record's `id` and `tags`
        are preserved, so the resulting payload is a no-op for those
        fields when handed to `service.update(identity, kc_pid, ...)`.

        Args:
            kc_record: The KC-user record dict (must carry `id`).
            orcid_data: An ORCID-derived dict in Names-payload shape
                (`identifiers`, `affiliations`, `props`, `name`,
                `given_name`, `family_name`).

        Returns:
            A merged update payload addressed by `kc_record["id"]`.
        """
        internal_id = kc_record.get("internal_id") or kc_record.get(
            "props", {}
        ).get("kcworks_user_id")
        merged = cast(
            NamesRecordDict,
            {
                "id": kc_record.get("id", ""),
                "internal_id": internal_id,
                "tags": list(kc_record.get("tags") or [KCNamesTag.USER]),
                "identifiers": union_dicts_by_key(
                    kc_record.get("identifiers", []),
                    orcid_data.get("identifiers", []),
                    key=self._identifier_key,
                ),
                "affiliations": union_dicts_by_key(
                    kc_record.get("affiliations", []),
                    orcid_data.get("affiliations", []),
                    key=self._affiliation_key,
                ),
                # `props["source"]` records what triggered insertion of a
                # `kcworks-cited` stub; carrying it onto a KC-user record
                # would leave false provenance behind.
                "props": merge_dicts_first_wins(
                    kc_record.get("props", {}),
                    orcid_data.get("props", {}),
                    exclude_from_secondary=("source",),
                ),
            },
        )
        for field in ("name", "given_name", "family_name"):
            kc_value = kc_record.get(field) or ""
            orcid_value = orcid_data.get(field) or ""
            if kc_value:
                merged[field] = kc_value
            elif orcid_value:
                merged[field] = orcid_value
        return merged

    # ------------------------------------------------------------------
    # Dedupe report
    # ------------------------------------------------------------------

    def merge_orcid_duplicates(
        self,
        *,
        identity: Identity | None = None,
        limit: int = 1000,
    ) -> dict[str, int]:
        """Auto-consolidate Names records that share an ORCID iD.

        Strategy
        --------
        A single OpenSearch `terms` aggregation on
        `identifiers.identifier` (`min_doc_count=2`) returns every
        identifier value that appears on two or more records, regardless
        of their `family_name` spelling. A `top_hits` sub-aggregation
        pulls the records back so consolidation runs in one round trip.

        The `identifiers` field is mapped as an `object` (not `nested`),
        which means a doc with both an `orcid` and a `kc_username`
        identifier is flattened at agg time, so the agg can return
        bucket keys that aren't ORCIDs (kc_usernames, ISNIs, etc.). For
        each bucket we therefore re-validate per member that the bucket
        key is actually carried with `scheme=orcid` in that record's
        `identifiers` list, and only consider members where it is. False
        buckets (e.g. shared kc_username, which can't actually happen
        since kc_username is the PID) silently fall away.

        Per real ORCID-collision bucket
        -------------------------------
        * `1 USER + N non-USER`: each non-USER record (CITED, untagged
          harvester, etc.) is folded into the USER record via
          `merge_cited_orcid_into_kc()`. The merge primitive deletes
          the non-USER stub on success; subsequent merges in the same
          bucket are fed the freshly-merged USER dict so each call sees
          the latest state.
        * `>1 USER`: refuses to auto-merge - two distinct KC-user
          records with the same ORCID is a real bad-data condition that
          needs human review. Counted under `multi_user_collisions`;
          surfaced separately by `find_duplicate_candidates()` on the
          same sweep.
        * `0 USER, >=2 non-USER`: no canonical merge target. Counted
          under `orphan_collisions`. In normal operation this should not
          arise (`upsert_cited_orcid_name` uses ORCID as PID so two
          CITED stubs cannot share one), but harvester-origin records
          or PID drift could produce it.

        Args:
            identity: Optional Invenio identity. Defaults to
                `system_identity`.
            limit: Maximum number of identifier-collision buckets
                returned by the aggregation.

        Returns:
            Stats dict::

                {
                    "merged": int,                 # successful merges
                    "multi_user_collisions": int,  # buckets with >1 USER
                    "orphan_collisions": int,      # buckets with 0 USER
                    "errors": int,                 # merge calls that returned None
                }
        """
        service = self.names_service
        identity = identity or system_identity
        stats = {
            "merged": 0,
            "multi_user_collisions": 0,
            "orphan_collisions": 0,
            "errors": 0,
        }

        try:
            search = service.create_search(
                identity=identity,
                record_cls=service.record_cls,
                search_opts=service.config.search,
                extra_filter=dsl.Q("exists", field="identifiers.identifier"),
            )
        except Exception:
            self.logger.warning(
                "merge_orcid_duplicates: create_search failed", exc_info=True
            )
            return stats

        search = search[:0]
        search.aggs.bucket(
            "by_identifier",
            "terms",
            field="identifiers.identifier",
            size=limit,
            min_doc_count=2,
        ).bucket(
            "members",
            "top_hits",
            size=self._top_hits_per_dedup_bucket,
        )

        try:
            response = search.execute()
        except Exception:
            self.logger.warning(
                "merge_orcid_duplicates: agg query failed", exc_info=True
            )
            return stats

        for bucket in response.aggregations.by_identifier.buckets:
            bucket_key = bucket.key.lower()
            members = [
                m
                for m in (
                    cast(NamesRecordDict, hit["_source"])
                    for hit in bucket.members.to_dict()["hits"]["hits"]
                )
                if self._record_carries_orcid(m, bucket_key)
            ]
            # The agg flattens object-mapped identifiers, so a bucket
            # may have <2 members carrying the key as scheme=orcid even
            # though the raw doc count was >=2 (e.g. one orcid match
            # plus a coincidental kc_username collision).
            if len(members) < 2:
                continue

            users = [m for m in members if KCNamesTag.USER in m.get("tags", [])]
            others = [m for m in members if KCNamesTag.USER not in m.get("tags", [])]

            if len(users) > 1:
                stats["multi_user_collisions"] += 1
                self.logger.warning(
                    "merge_orcid_duplicates: %d USER records share ORCID %s "
                    "(uuids=%s); deferring to human review",
                    len(users),
                    bucket_key,
                    [u["uuid"] for u in users],
                )
                continue

            if not users:
                stats["orphan_collisions"] += 1
                self.logger.warning(
                    "merge_orcid_duplicates: %d non-USER records share ORCID %s "
                    "(uuids=%s) with no USER record to merge into",
                    len(others),
                    bucket_key,
                    [o["uuid"] for o in others],
                )
                continue

            kc_state = users[0]
            for other_record in others:
                merged = self.merge_cited_orcid_into_kc(
                    kc_state, cited_data=other_record, identity=identity
                )
                if merged is None:
                    stats["errors"] += 1
                    self.logger.warning(
                        "merge_orcid_duplicates: merge of %s into %s returned "
                        "None for ORCID %s",
                        other_record["uuid"],
                        kc_state["uuid"],
                        bucket_key,
                    )
                    continue
                kc_state = merged
                stats["merged"] += 1

        return stats

    @staticmethod
    def _record_carries_orcid(record: NamesRecordDict, normalized_value: str) -> bool:
        """Tell whether `record` carries `normalized_value` as its ORCID.

        The agg's bucket key is the OS-normalized form of the identifier
        (lowercased, asciifolded, punctuation stripped); the record's
        `identifiers` list stores the original. We compare apples to
        apples by stripping non-alphanumeric chars from each candidate
        identifier on the record before lowercasing.

        Args:
            record: A Names record as indexed in OpenSearch.
            normalized_value: The bucket key from the OS terms agg.

        Returns:
            `True` when the record has an `identifiers` entry with
            `scheme == "orcid"` whose normalized value equals
            `normalized_value`. `False` otherwise.
        """
        for ident in record.get("identifiers", []):
            if ident["scheme"].lower() != "orcid":
                continue
            stripped = re.sub(r"[^0-9a-z]", "", ident["identifier"].lower())
            if stripped == normalized_value:
                return True
        return False

    def _read_dedup_bookmark(self) -> datetime | None:
        """Return the cached cutoff for the next incremental dedup sweep.

        Looks up `_DEDUP_BOOKMARK_KEY` via `invenio_cache.current_cache`.
        A missing key, an unreadable cache, or a malformed value all
        return `None` so the caller falls back to a full sweep — that's
        the only safe behavior when we cannot trust the bookmark.

        Cache failures are logged once at warning level so an operator
        notices a misconfigured backend, but the call never raises:
        dedup is a maintenance job and must not abort just because the
        cache is down.

        Returns:
            The previously stored sweep timestamp (timezone-aware UTC),
            or `None` when no usable bookmark is available.
        """
        try:
            from invenio_cache import current_cache

            raw = current_cache.get(_DEDUP_BOOKMARK_KEY)
        except Exception:
            self.logger.warning(
                "names_sync: failed to read dedup bookmark; "
                "next run will be a full sweep",
                exc_info=True,
            )
            return None
        if not raw:
            return None
        try:
            parsed = datetime.fromisoformat(str(raw))
        except (TypeError, ValueError):
            self.logger.warning(
                "names_sync: dedup bookmark unparseable (%r); "
                "next run will be a full sweep",
                raw,
            )
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed

    def _write_dedup_bookmark(self, ts: datetime) -> None:
        """Persist the next-sweep cutoff to `invenio_cache`.

        Stores `ts` as an ISO 8601 UTC string under
        `_DEDUP_BOOKMARK_KEY` with `timeout=0` (never expire). A cache
        write failure is logged but otherwise swallowed; the next run
        will simply do a full sweep when it can't read a fresh
        bookmark, which is benign.

        Args:
            ts: Timestamp the next incremental run should treat as the
                lower bound. Naive datetimes are coerced to UTC. In
                normal usage callers pass the *start* time of the
                current sweep so any record updated during the sweep
                gets re-evaluated next time.
        """
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        try:
            from invenio_cache import current_cache

            current_cache.set(_DEDUP_BOOKMARK_KEY, ts.isoformat(), timeout=0)
        except Exception:
            self.logger.warning(
                "names_sync: failed to write dedup bookmark; "
                "next run will be a full sweep",
                exc_info=True,
            )

    def find_duplicate_candidates(
        self,
        *,
        identity: Identity | None = None,
        limit: int | None = None,
        since: datetime | None = None,
        full_sweep: bool = False,
    ) -> list[dict[str, Any]]:
        """Return likely-duplicate Names record pairs for human review.

        Strategy
        --------
        A single OpenSearch request carries two sibling top-level
        `terms` aggregations:

        1. *Token pass* (`by_part`): aggregates on the multi-valued
           `props.family_part_tokens.keyword` (with `min_doc_count=2`).
           Each bucket key is either the full normalized family form
           or any one constituent piece. Every unique unordered pair
           in a bucket is scored with `_score_bucket_pairs(...,
           family_comparison="token")`, which classifies the hit as
           full-family or partial-family (the latter discounted by
           `PARTIAL_FAMILY_DISCOUNT`).

        2. *Phonetic pass* (`by_phonetic`): aggregates on
           `props.family_phonetic_tokens.keyword` (per-piece Metaphone
           codes). Catches spelling variants the token normalization
           cannot, e.g. `Smith`/`Smyth` (both `SM0`) or
           `OBrien`/`OBrian` (both `OBRN`). Hits get
           `PHONETIC_FAMILY_DISCOUNT` applied.

        Each bucket's `top_hits` sub-aggregation pulls the records
        back, so the whole sweep is a single OS round trip regardless
        of corpus size. Within either pass `PersonNameComparator`
        does the given-name scoring; pairs with both `given_name`
        values empty are surfaced with a `family_*+given_absent`
        `score_method` so a reviewer can decide.

        TODO: `PersonNameComparator` consults a vendored ~70k-row
        given-name variants table (see `data/given_name_variants/`)
        as an in-memory inverted index. The first comparison this
        method makes loads that table into the worker process (~1 s,
        ~230 MB resident) and caches it for the worker's lifetime.
        That is acceptable for a low-frequency Celery dedup job but
        not for a hot-path service. Before any code path outside the
        nightly dedup sweep starts comparing names, replace the
        in-memory dict with a properly-indexed lookup (e.g., an
        OpenSearch index of `(token -> canonical_roots)` documents,
        or a pre-built sqlite/dbm file shipped beside the CSV).

        Because `family_part_tokens` and `family_phonetic_tokens` are
        both multi-valued, the same pair often appears in multiple
        buckets across both passes (e.g., two `García López` records
        share `garcia lopez`, `garcia`, `lopez`, plus their phonetic
        codes). After collecting everything we deduplicate by
        record-pair and keep the highest-scoring entry, so token-exact
        full-family hits naturally win out over partial / phonetic
        ones.

        `props.family_part_tokens` and `props.family_phonetic_tokens`
        are populated by the payload builders at write time; records
        that pre-date the fields (or that come from upstream paths we
        do not touch) are silently invisible to the corresponding
        pass until something causes them to be rewritten. That is by
        design: we do not run a backfill. Note that the absence of
        `family_phonetic_tokens` on older records is precisely where
        the phonetic pass's value would otherwise show up most.

        Composition
        -----------
        Callers should run `merge_orcid_duplicates()` before this method
        so any pair sharing an ORCID iD has already been auto-consolidated
        and does not show up here. Pairs that survive that pass and still
        share an ORCID are surfaced with `shared_orcid: True`; that means
        the auto-merge could not run (multiple `USER` records with the
        same ORCID, no `USER` to merge into, etc.) and the pair genuinely
        needs human eyes.

        Excluded pairs
        --------------
        Pairs previously dismissed via `dismiss_duplicate_pair()` (either
        side carries the other's UUID in `props.dismissed_duplicates`)
        are dropped so operators do not re-review them.

        Incremental sweeps
        ------------------
        By default, the call resolves a bookmark from `invenio_cache`
        (key `_DEDUP_BOOKMARK_KEY`) carrying the start time of the
        previous successful sweep. Candidate pairs where neither side
        has been updated at or after that bookmark are filtered out
        before scoring is persisted, so a nightly sweep does only the
        work the corpus's recent churn actually justifies. The bookmark
        is rewritten to the *current* sweep's start time after the
        scoring loop completes; a sweep that aborts (e.g. raises before
        reaching that point) leaves the prior bookmark in place, so the
        next run repeats the gap.

        Pass `since` to override the bookmark explicitly (useful for
        backfills and ad-hoc range checks). Pass `full_sweep=True` to
        ignore any stored bookmark and process the whole corpus; this
        still rewrites the bookmark on success, so a periodic full
        sweep collapses any drift that incremental runs missed without
        forfeiting the incremental cadence afterwards. Filtering happens
        at pair-time rather than aggregation-time so a stale record on
        one side of a pair still surfaces when its partner is freshly
        touched.

        A `full_sweep` run additionally performs the corpus-wide GC of
        stale `possible_duplicates` cross-references via
        `_prune_stale_cross_refs`. That step is only run on full
        sweeps because it requires enumerating every live UUID, and
        because deleted Names records are rare enough that piggybacking
        the periodic full sweep is the right cadence.

        Args:
            identity: Optional Invenio identity. Defaults to
                `system_identity`.
            limit: Optional safety cap on the number of family-name
                buckets collected per dedup pass (token, phonetic).
                When `None` (default) each pass paginates exhaustively
                via composite aggregation, so every bucket with at
                least two records is considered. When set, each pass
                stops paging once it has collected `limit` buckets and
                logs that the cap fired.
            since: Optional explicit cutoff timestamp. When given,
                overrides the cached bookmark for this call. Naive
                datetimes are treated as UTC.
            full_sweep: When `True`, ignore any stored bookmark and
                consider every candidate pair. The new bookmark is
                still written on success so the next incremental run
                resumes from this sweep's start time.

        Returns:
            A list of candidate-pair dicts, sorted by `score`
            descending. Each dict carries `score`, `score_method`,
            `family_token` (the canonical singular form from
            `record_a`'s `props`), `shared_orcid`, and
            `record_a`/`record_b`. The two `record_*` entries are the
            full Names records as indexed (`NamesRecordDict` shape).

            `score_method` is one of six labels in the form
            `family_<signal>+given_<signal>`, naming what was
            compared on each axis::

                family_exact+given_fuzzy      family_exact+given_absent
                family_partial+given_fuzzy    family_partial+given_absent
                family_phonetic+given_fuzzy   family_phonetic+given_absent

            * `family_exact`: the token-pass bucket key matched both
              records' full canonical family form (no discount).
            * `family_partial`: the token-pass bucket key matched one
              piece of a multi-part / hyphenated family name on at
              least one side (`PARTIAL_FAMILY_DISCOUNT` applied).
            * `family_phonetic`: the phonetic-pass bucket key
              matched per-piece Metaphone codes on both sides
              (`PHONETIC_FAMILY_DISCOUNT` applied).
            * `given_fuzzy`: `PersonNameComparator` produced the
              given-name component of the score.
            * `given_absent`: both records had no `given_name`, so
              the given-name component fell back to
              `EMPTY_GIVEN_NAME_SCORE` and the threshold was
              bypassed.
        """
        identity = identity or system_identity
        threshold = GIVEN_NAME_SIMILARITY_THRESHOLD

        sweep_started_at = datetime.now(UTC)
        bookmark: datetime | None
        if full_sweep:
            bookmark = None
        elif since is not None:
            bookmark = since
        else:
            bookmark = self._read_dedup_bookmark()

        buckets_by_pass = self._fetch_dedup_buckets(identity=identity, limit=limit)

        # Deduplicate pairs that surface in multiple buckets (the full
        # family form + each piece, plus each phonetic code) across
        # both passes. Key: frozenset of the two record UUIDs; value:
        # highest-scoring candidate dict so far.
        best_by_pair: dict[frozenset[str], dict[str, Any]] = {}

        for family_comparison in ("token", "phonetic"):
            for bucket_key, members in buckets_by_pass[family_comparison]:
                for cand in self._score_bucket_pairs(
                    members,
                    bucket_key,
                    threshold,
                    family_comparison=family_comparison,
                ):
                    if bookmark is not None and not _pair_touches_recent(
                        cand, bookmark
                    ):
                        continue
                    key = frozenset((
                        cand["record_a"]["uuid"],
                        cand["record_b"]["uuid"],
                    ))
                    existing = best_by_pair.get(key)
                    if existing is None or cand["score"] > existing["score"]:
                        best_by_pair[key] = cand

        candidates = list(best_by_pair.values())
        candidates.sort(key=lambda c: c["score"], reverse=True)
        for c in candidates:
            self._set_duplicates_for_pair(identity, **c)
        # Remove stale `possible_duplicates` cross-references to records
        # that no longer exist in the Names index.
        if full_sweep:
            self._prune_stale_cross_refs(identity=identity)
        self._write_dedup_bookmark(sweep_started_at)
        return candidates

    def _fetch_dedup_buckets(
        self,
        *,
        identity,
        limit: int | None = None,
    ) -> dict[str, list[tuple[str, list[NamesRecordDict]]]]:
        """Page exhaustively through both dedup-pass bucket spaces.

        Each pass uses a `composite` aggregation paged via `after_key`,
        so every family-token / phonetic-code bucket with at least two
        records is enumerated rather than only the top-N by doc_count.
        A `bucket_selector` pipeline agg drops singletons server-side.
        Each composite bucket carries a `top_hits` sub-aggregation
        pulling the full record source so scoring runs in Python
        without additional OS round trips.

        The two passes share the same base query (Names permission
        filter + `exists props.family_part_tokens`) but each needs its
        own `after_key` cursor, so they run as separate paged loops.
        The `exists` narrowing is keyed on `props.family_part_tokens`
        only because the payload builders always populate both fields
        together; a record with phonetic tokens always has part
        tokens. The phonetic pass simply produces no buckets for docs
        that lack `props.family_phonetic_tokens` (e.g. when Metaphone
        returned an empty code for every piece).

        Logs and returns empty bucket lists for both passes on any
        OpenSearch error so the caller's downstream logic stays
        well-defined.

        Args:
            identity: Invenio identity to scope the search.
            limit: Optional safety cap on buckets collected per pass.
                When `None` (default) each pass paginates exhaustively.
                When set, paging stops once a pass has collected
                `limit` buckets and an info log records that the cap
                fired.

        Returns:
            A dict::

                {
                    "token":    [(bucket_key, [members]), ...],
                    "phonetic": [(bucket_key, [members]), ...],
                }
        """
        empty: dict[str, list[tuple[str, list[NamesRecordDict]]]] = {
            "token": [],
            "phonetic": [],
        }
        out: dict[str, list[tuple[str, list[NamesRecordDict]]]] = {
            "token": [],
            "phonetic": [],
        }
        service = self.names_service
        for pass_name, agg_name, field in (
            ("token", "by_part", "props.family_part_tokens.keyword"),
            ("phonetic", "by_phonetic", "props.family_phonetic_tokens.keyword"),
        ):
            after: dict | None = None
            cap_hit = False
            while not cap_hit:
                # `create_search()` returns a permission-filtered DSL
                # `Search` instance without the params/facets/sort
                # interpreters `search()` would layer on. We attach
                # aggregations directly because the high-level
                # `search()` API does not surface ad-hoc aggs and the
                # configured Names search options have no facet for
                # the dedup-index fields.
                try:
                    search = service.create_search(
                        identity=identity,
                        record_cls=service.record_cls,
                        search_opts=service.config.search,
                        extra_filter=dsl.Q("exists", field="props.family_part_tokens"),
                    )
                except Exception:
                    self.logger.warning(
                        "find_duplicate_candidates: create_search failed (pass=%s)",
                        pass_name,
                        exc_info=True,
                    )
                    return empty

                search = search.extra(size=0)
                composite_kwargs: dict[str, Any] = {
                    "sources": [{"term": {"terms": {"field": field}}}],
                    "size": _DEDUP_PAGE_SIZE,
                }
                if after is not None:
                    composite_kwargs["after"] = after
                composite = search.aggs.bucket(
                    agg_name, "composite", **composite_kwargs
                )
                composite.bucket(
                    "members",
                    "top_hits",
                    size=self._top_hits_per_dedup_bucket,
                )
                composite.bucket(
                    "ge_two",
                    "bucket_selector",
                    buckets_path={"count": "_count"},
                    script="params.count >= 2",
                )

                try:
                    response = search.execute()
                except Exception:
                    self.logger.warning(
                        "find_duplicate_candidates: agg query failed (pass=%s)",
                        pass_name,
                        exc_info=True,
                    )
                    return empty

                agg_response = response.aggregations[agg_name]
                for bucket in agg_response.buckets:
                    members = cast(
                        list[NamesRecordDict],
                        [
                            hit["_source"]
                            for hit in bucket.members.to_dict()["hits"]["hits"]
                        ],
                    )
                    out[pass_name].append((bucket.key.term, members))
                    if limit is not None and len(out[pass_name]) >= limit:
                        self.logger.info(
                            "find_duplicate_candidates: limit=%d reached "
                            "on pass=%s, stopping pagination",
                            limit,
                            pass_name,
                        )
                        cap_hit = True
                        break
                if cap_hit:
                    break

                next_after = getattr(agg_response, "after_key", None)
                if next_after is None:
                    break
                # AttrDict -> plain dict for the next request body.
                after = (
                    next_after.to_dict()
                    if hasattr(next_after, "to_dict")
                    else dict(next_after)
                )
        return out

    def _score_bucket_pairs(
        self,
        members: list[NamesRecordDict],
        bucket_key: str,
        threshold: float,
        *,
        family_comparison: Literal["token", "phonetic"] = "token",
    ) -> list[dict[str, Any]]:
        """Score every unique unordered pair within one bucket.

        Two flavors of bucket are scored by this function, selected by
        `family_comparison`:

        * `"token"` (default): the bucket key came from the
          `props.family_part_tokens` aggregation. Each pair is
          classified as full-family or partial-family by comparing the
          bucket key against element 0 of each side's
          `family_part_tokens` (the full canonical form). Partial
          hits get a `PARTIAL_FAMILY_DISCOUNT` multiplier on the
          final score and a distinct `score_method` value.

        * `"phonetic"`: the bucket key is a Metaphone code from the
          `props.family_phonetic_tokens` aggregation. We do not
          sub-classify full vs partial here — phonetic matches are
          inherently fuzzier — and apply a single
          `PHONETIC_FAMILY_DISCOUNT` to all hits in the pass.

        For pairs where both `given_name` values are empty, the
        comparator cannot discriminate; we surface them anyway with a
        `family_*+given_absent` `score_method` and bypass the
        threshold so a reviewer can decide. For all other pairs the
        `PersonNameComparator` score (post-discount) is checked
        against `threshold`. See `find_duplicate_candidates` for the
        full table of `score_method` values.

        Args:
            members: Records collected from one OpenSearch agg bucket.
            bucket_key: The agg bucket's term value (a family-name
                piece for the token pass, a Metaphone code for the
                phonetic pass).
            threshold: Minimum score required to emit a pair when the
                given-name comparator was used. `given_absent` pairs
                bypass this check.
            family_comparison: Which dedup pass produced the bucket;
                drives the discount and `score_method` selection.

        Returns:
            A possibly-empty list of candidate-pair dicts in the
            public shape documented on `find_duplicate_candidates`.
        """
        out: list[dict[str, Any]] = []
        for rec_a, rec_b in combinations(members, 2):
            if rec_a["uuid"] == rec_b["uuid"]:
                continue
            dismissed_a = self._record_dismissed_uuids(rec_a)
            dismissed_b = self._record_dismissed_uuids(rec_b)
            if rec_a["uuid"] in dismissed_b or rec_b["uuid"] in dismissed_a:
                continue

            if family_comparison == "phonetic":
                discount = PHONETIC_FAMILY_DISCOUNT
                given_method = "family_phonetic+given_fuzzy"
                empty_method = "family_phonetic+given_absent"
            else:
                full_a = self._record_full_family_token(rec_a)
                full_b = self._record_full_family_token(rec_b)
                is_full_family = bool(full_a) and bucket_key == full_a == full_b
                discount = 1.0 if is_full_family else PARTIAL_FAMILY_DISCOUNT
                given_method = (
                    "family_exact+given_fuzzy"
                    if is_full_family
                    else "family_partial+given_fuzzy"
                )
                empty_method = (
                    "family_exact+given_absent"
                    if is_full_family
                    else "family_partial+given_absent"
                )

            given_a = rec_a.get("given_name", "")
            given_b = rec_b.get("given_name", "")
            both_empty = not given_a and not given_b

            if both_empty:
                score = EMPTY_GIVEN_NAME_SCORE * discount
                method = empty_method
            else:
                raw = self._given_name_comparator.compare(given_a, given_b).score
                score = raw * discount
                if score < threshold:
                    continue
                method = given_method

            orcid_a = next(
                iter([
                    r["identifier"]
                    for r in rec_a.get("identifiers", []) or []
                    if r["scheme"].lower() == "orcid"
                ]),
                "",
            )
            orcid_b = next(
                iter([
                    r["identifier"]
                    for r in rec_b.get("identifiers", []) or []
                    if r["scheme"].lower() == "orcid"
                ]),
                "",
            )
            shared_orcid = bool(orcid_a) and orcid_a.lower() == orcid_b.lower()
            out.append({
                "score": round(score, 4),
                "score_method": method,
                "family_token": rec_a.get("props", {}).get("family_token", ""),
                "shared_orcid": shared_orcid,
                "record_a": rec_a,
                "record_b": rec_b,
            })
        return out

    @staticmethod
    def _record_full_family_token(record: NamesRecordDict) -> str:
        """Return the canonical full family token for a record.

        That's element 0 of `props.family_part_tokens` (the helper
        always puts the full normalized form first). Falls back to
        the singular `props.family_token` when the multi-valued field
        is absent (e.g., older records). Returns `""` if neither is
        present.
        """
        props = record.get("props", {})
        parts = props.get("family_part_tokens") or []
        if isinstance(parts, str):
            parts = json.loads(parts)
        if parts:
            return parts[0]
        return props.get("family_token", "")

    @staticmethod
    def _record_dismissed_uuids(record: NamesRecordDict) -> set[str]:
        """Return the set of Names UUIDs the operator has dismissed for `record`."""
        return {str(u) for u in record.get("props", {}).get("dismissed_duplicates", [])}

    def _set_duplicates_for_pair(
        self,
        identity: Identity | None,
        score: float,
        score_method: str,
        family_token: str,
        shared_orcid: str,
        record_a: NamesRecordDict,
        record_b: NamesRecordDict,
    ) -> bool:
        """Add or refresh a possible-duplicate cross-reference between two Names.

        For each side of the pair, sets
        `props.possible_duplicates[other_uuid]` to
        `[score, score_method]`, overwriting any previous entry. The
        cross-reference is symmetric: each side records the other. The
        candidate scores flowing from `find_duplicate_candidates`
        already represent the best across all buckets and passes for
        the pair *in this sweep*, and each sweep operates on the
        current state of both records — so the stored entry always
        reflects this run's decision rather than a stale prior
        maximum.

        Persists each side via `NamesService.update`, but only if its
        entry actually changed. A pair whose stored entry already
        equals `[score, score_method]` on both sides is a no-op that
        returns `True` without an OS round-trip.

        Skips (returns `False` without writing) when either side has
        dismissed the other (UUID present in the other's
        `props.dismissed_duplicates`), or when `record_a` and
        `record_b` resolve to the same record.

        Args:
            identity: Optional Invenio identity. Defaults to
                `system_identity`.
            score: Numerical similarity score for this pair.
            score_method: Comparison-strategy code that produced
                `score`.
            family_token: Canonical singular family form. Currently
                informational; accepted so the candidate dict from
                `find_duplicate_candidates` can be passed via `**c`.
            shared_orcid: Same-ORCID flag. Currently informational,
                same reason as `family_token`.
            record_a: Full Names record (search-index shape).
            record_b: Full Names record (search-index shape).

        Returns:
            `True` on successful persistence, including the no-op case
            when neither side's entry needed to change. `False` when
            the pair is the same record, when either side has
            dismissed the other, or when a `service.update` call
            raises (the cause is logged).
        """
        identity = identity or system_identity
        pid_a, pid_b = record_a["id"], record_b["id"]
        if pid_a == pid_b:
            self.logger.warning(
                "set_duplicates_for_pair: refusing to act on a record "
                "paired with itself (pid=%s)",
                pid_a,
            )
            return False

        uuid_a = record_a["uuid"]
        uuid_b = record_b["uuid"]

        if uuid_a in record_b["props"].get(
            "dismissed_duplicates", []
        ) or uuid_b in record_a["props"].get("dismissed_duplicates", []):
            return False

        new_entry = [score, score_method]
        sides_to_persist: list[tuple[str, NamesRecordDict]] = []
        for rec, other_uuid, pid in (
            (record_a, uuid_b, pid_a),
            (record_b, uuid_a, pid_b),
        ):
            pd = rec["props"].setdefault("possible_duplicates", {})
            if pd.get(other_uuid) != new_entry:
                pd[other_uuid] = new_entry
                sides_to_persist.append((pid, rec))

        if not sides_to_persist:
            return True

        service = self.names_service
        try:
            for pid, rec in sides_to_persist:
                service.update(identity, pid, rec)
        except Exception:
            self.logger.warning(
                "set_duplicates_for_pair: failed to update records "
                "(pid_a=%s, pid_b=%s)",
                pid_a,
                pid_b,
                exc_info=True,
            )
            return False

        self.logger.info(
            "set_duplicates_for_pair: %s (uuid %s) <-> %s (uuid %s), (%s, %s)",
            pid_a,
            uuid_a,
            pid_b,
            uuid_b,
            str(score),
            score_method,
        )
        return True

    # ------------------------------------------------------------------
    # Stale-cross-reference GC (full-sweep only)
    # ------------------------------------------------------------------

    def _fetch_live_uuids(self, *, identity: Identity) -> set[str]:
        """Return the set of UUIDs currently present in the Names index.

        Uses the standard search service entry point so the
        permission filter and any soft-delete exclusion configured on
        the Names index apply automatically: a record indexed and
        readable by the caller's identity is "live" for prune
        purposes; anything else is gone.

        Projects only the `uuid` field via `_source` filtering so the
        per-doc payload stays small even on large corpora; iteration
        is via `scan()` (scroll API), which paginates server-side and
        avoids holding the full result set in OS memory.

        Failures (search build error or scroll error) log a warning
        and return an empty set. The caller treats the empty set as a
        signal to bail rather than declare the entire corpus stale.

        Args:
            identity: Invenio identity to scope the search.

        Returns:
            All Names record UUIDs visible to `identity`. Empty set
            on any error.
        """
        service = self.names_service
        try:
            search = service.create_search(
                identity=identity,
                record_cls=service.record_cls,
                search_opts=service.config.search,
            )
        except Exception:
            self.logger.warning(
                "prune_stale_cross_refs: live-UUID create_search failed",
                exc_info=True,
            )
            return set()
        search = search.source(["uuid"])
        try:
            return {str(hit.uuid) for hit in search.scan()}
        except Exception:
            self.logger.warning(
                "prune_stale_cross_refs: live-UUID scan failed",
                exc_info=True,
            )
            return set()

    def _fetch_records_with_cross_refs(
        self, *, identity: Identity
    ) -> list[NamesRecordDict]:
        """Return Names records that currently carry a `possible_duplicates` map.

        Filtered server-side via `exists: props.possible_duplicates`
        so the prune phase only handles the slice of the corpus that
        actually has cross-references to potentially clean up. Pulls
        the full source for each match because the prune step needs
        the existing dict to mutate it in place before the write-back.

        Iteration is via `scan()`; for any reasonable corpus the slice
        of records carrying cross-refs should be small enough to
        materialize, but `scan()` keeps us safe if it isn't.

        Args:
            identity: Invenio identity to scope the search.

        Returns:
            List of `NamesRecordDict`-shaped records as indexed.
            Empty list on any error.
        """
        service = self.names_service
        try:
            search = service.create_search(
                identity=identity,
                record_cls=service.record_cls,
                search_opts=service.config.search,
                extra_filter=dsl.Q("exists", field="props.possible_duplicates"),
            )
        except Exception:
            self.logger.warning(
                "prune_stale_cross_refs: cross-ref create_search failed",
                exc_info=True,
            )
            return []
        try:
            return [cast(NamesRecordDict, hit.to_dict()) for hit in search.scan()]
        except Exception:
            self.logger.warning(
                "prune_stale_cross_refs: cross-ref scan failed",
                exc_info=True,
            )
            return []

    def _prune_stale_cross_refs(
        self, *, identity: Identity | None = None
    ) -> dict[str, int]:
        """Drop `possible_duplicates` entries pointing to deleted records.

        Names records are rarely hard-deleted, but when one is, every
        cross-reference to its UUID becomes a dangling pointer in
        another record's `props.possible_duplicates` dict. This method
        is the periodic GC for those pointers and is intended to run
        from `find_duplicate_candidates` only when `full_sweep=True`.

        Algorithm:

        1. Query the Names index for the set of all live UUIDs
           (`_fetch_live_uuids`).
        2. Query the Names index for every record that currently has
           a `props.possible_duplicates` map
           (`_fetch_records_with_cross_refs`).
        3. For each such record, drop any `possible_duplicates` key
           whose UUID is not in the live set, then `service.update`
           it back. Records with no stale entries are left alone — no
           gratuitous writes.

        A defensive empty-live-set check bails before mutating
        anything. If the live-UUID query failed silently and returned
        an empty set, treating every cross-ref as stale would nuke
        the entire `possible_duplicates` graph in one sweep; the
        check makes that impossible.

        Per-record write failures are logged but do not abort the
        prune walk; one bad write shouldn't strand the rest of the
        cleanup.

        Note that this only handles deletions of Names records
        themselves. User-account deletions deliberately do not cascade
        into Names deletion in KCWorks (the Names entry is the
        authority record and persists across user lifecycle events),
        so the corresponding cross-refs survive a user delete on
        purpose.

        Args:
            identity: Optional Invenio identity. Defaults to
                `system_identity`.

        Returns:
            A counters dict with three keys:

            * `inspected`: records examined (i.e. records that
              carried a `possible_duplicates` map at scan time).
            * `pruned`: records whose stored doc was actually
              rewritten (had at least one stale entry).
            * `keys_dropped`: total stale entries removed across all
              `pruned` records.
        """
        identity = identity or system_identity

        live_uuids = self._fetch_live_uuids(identity=identity)
        if not live_uuids:
            self.logger.warning(
                "prune_stale_cross_refs: live-UUID set empty; "
                "skipping prune to avoid clearing every cross-reference"
            )
            return {"inspected": 0, "pruned": 0, "keys_dropped": 0}

        inspected = 0
        pruned = 0
        keys_dropped = 0
        for rec in self._fetch_records_with_cross_refs(identity=identity):
            inspected += 1
            pd = rec.get("props", {}).get("possible_duplicates")
            if not isinstance(pd, dict):
                continue
            stale = [u for u in pd if u not in live_uuids]
            if not stale:
                continue
            for u in stale:
                del pd[u]
            try:
                self.names_service.update(identity, rec["id"], rec)
            except Exception:
                self.logger.warning(
                    "prune_stale_cross_refs: update failed (pid=%s)",
                    rec.get("id"),
                    exc_info=True,
                )
                continue
            pruned += 1
            keys_dropped += len(stale)

        if pruned:
            self.logger.info(
                "prune_stale_cross_refs: inspected=%d pruned=%d keys_dropped=%d",
                inspected,
                pruned,
                keys_dropped,
            )
        return {
            "inspected": inspected,
            "pruned": pruned,
            "keys_dropped": keys_dropped,
        }

    # ------------------------------------------------------------------
    # Dismissed-duplicate registry
    # ------------------------------------------------------------------

    @staticmethod
    def _record_uuid(item) -> str:
        """Return the model UUID (`id` column) for a Names `RecordItem`.

        The Names vocabulary uses `ModelPIDField` configured with
        `pid_field_kwargs={"model_field_name": "pid"}`, which means
        the schema-level `id` and the search-doc `id` both expose
        the PID, not the underlying database row UUID. The actual
        UUID lives on the SQLAlchemy model and is what we want to use
        as a stable, opaque key for the dismissed-duplicates registry.
        """
        return str(item._record.id)  # noqa: SLF001

    def _set_dismissed_for_pair(
        self,
        pid_a: str,
        pid_b: str,
        *,
        identity: Identity,
        add: bool,
    ) -> bool:
        """Shared backend for dismiss/undismiss of a Names duplicate pair.

        Reads both records, mutates each side's
        `props.dismissed_duplicates` to add or remove the other
        side's UUID, and persists via the Names service.

        Returns:
            `True` on success (including idempotent no-ops).
            `False` when either PID is missing or the underlying
            update fails (the cause is logged).
        """
        if pid_a == pid_b:
            self.logger.warning(
                "set_dismissed_for_pair: refusing to act on a record "
                "paired with itself (pid=%s)",
                pid_a,
            )
            return False

        service = self.names_service
        item_a = self._read_existing(identity, pid_a)
        item_b = self._read_existing(identity, pid_b)
        if item_a is None or item_b is None:
            self.logger.warning(
                "set_dismissed_for_pair: missing record (pid_a=%s "
                "found=%s, pid_b=%s found=%s)",
                pid_a,
                item_a is not None,
                pid_b,
                item_b is not None,
            )
            return False

        uuid_a = str(item_a._record.id)
        uuid_b = str(item_b._record.id)
        rec_a = item_a.to_dict()
        rec_b = item_b.to_dict()

        for rec, other_uuid in ((rec_a, uuid_b), (rec_b, uuid_a)):
            existing = set(rec["props"].get("dismissed_duplicates", []))
            rec["props"]["dismissed_duplicates"] = list(
                existing | {other_uuid} if add else existing - {other_uuid}
            )
            # When dismissing a pair, also drop any standing
            # `possible_duplicates` cross-reference so the dismissal
            # immediately removes the pair from the review surface
            # (rather than waiting for the next dedup sweep to notice
            # the dismissal). Undismissal is asymmetric here on
            # purpose: the next sweep is what re-establishes
            # `possible_duplicates`, scored against the records'
            # current state; we don't want to fabricate a stale entry.
            if add:
                pd = rec["props"].get("possible_duplicates")
                if isinstance(pd, dict):
                    pd.pop(other_uuid, None)

        try:
            service.update(identity, pid_a, rec_a)
            service.update(identity, pid_b, rec_b)
        except Exception:
            self.logger.warning(
                "set_dismissed_for_pair: failed to update records "
                "(pid_a=%s, pid_b=%s, add=%s)",
                pid_a,
                pid_b,
                add,
                exc_info=True,
            )
            return False

        self.logger.info(
            "set_dismissed_for_pair: %s pair %s (%s) <-> %s (%s)",
            "dismissed" if add else "un-dismissed",
            pid_a,
            uuid_a,
            pid_b,
            uuid_b,
        )
        return True

    def dismiss_duplicate_pair(
        self,
        pid_a: str,
        pid_b: str,
        *,
        identity: Identity | None = None,
    ) -> bool:
        """Mark two Names records as not-duplicates of each other.

        Records each record's UUID in the *other*'s
        `props.dismissed_duplicates` list so that
        `find_duplicate_candidates()` will skip the pair on
        subsequent runs. The dismissal is two-sided and permanent
        until reversed by `undismiss_duplicate_pair()`.

        Args:
            pid_a: PID (`id`) of one Names record.
            pid_b: PID (`id`) of the other Names record.
            identity: Optional Invenio identity. Defaults to
                `system_identity`.

        Returns:
            `True` on success (including idempotent re-dismissals).
            `False` if either PID does not exist or an update fails.
        """
        return self._set_dismissed_for_pair(
            pid_a,
            pid_b,
            identity=identity or system_identity,
            add=True,
        )

    def undismiss_duplicate_pair(
        self,
        pid_a: str,
        pid_b: str,
        *,
        identity: Identity | None = None,
    ) -> bool:
        """Reverse a previous `dismiss_duplicate_pair()` call.

        Removes each record's UUID from the *other*'s
        `props.dismissed_duplicates` list. Idempotent: calling on a
        pair that was not dismissed is a no-op that still returns
        `True`.

        Args:
            pid_a: PID (`id`) of one Names record.
            pid_b: PID (`id`) of the other Names record.
            identity: Optional Invenio identity. Defaults to
                `system_identity`.

        Returns:
            `True` on success. `False` if either PID does not
            exist or an update fails.
        """
        return self._set_dismissed_for_pair(
            pid_a,
            pid_b,
            identity=identity or system_identity,
            add=False,
        )

    def list_duplicate_pairs(
        self,
        *,
        identity: Identity | None = None,
    ) -> list[dict[str, Any]]:
        """Return all Names record pairs currently flagged as possible duplicates.

        Reads the persisted output of `find_duplicate_candidates` /
        `_set_duplicates_for_pair`: every record carrying a non-empty
        `props.possible_duplicates` map contributes one row per
        cross-reference, deduped to one row per symmetric edge.

        Reuses `_fetch_records_with_cross_refs`, so the OS scan is
        already filtered server-side to the slice of the corpus that
        actually carries cross-refs (no full-index walk).

        Each side of a pair stores its own `[score, score_method]`
        copy. Both sides are written in the same `_set_duplicates_for_pair`
        call, so they should always agree, but a partial-failure mode
        can desync them. When the two stored entries disagree, this
        method takes the **higher** score (and its method), and logs
        a warning so the desync is visible. One-sided edges (the
        partner record has no matching reverse entry) are likewise
        logged and skipped — that condition usually means the partner
        was deleted between the two writes or one update failed.

        Args:
            identity: Optional Invenio identity. Defaults to
                `system_identity`.

        Returns:
            A list of dicts, sorted by score descending and then by
            `(a_pid, b_pid)` for stable ordering. Each row is shaped::

                {
                    "score": 0.95,
                    "score_method": "family_exact+given_fuzzy",
                    "a_uuid": "...", "a_pid": "kc|jdoe",  "a_name": "Doe, John",
                    "b_uuid": "...", "b_pid": "0000-...", "b_name": "Doe, Jonathan",
                }
        """
        identity = identity or system_identity
        records = self._fetch_records_with_cross_refs(identity=identity)

        by_uuid: dict[str, tuple[str, str | None]] = {}
        side_entries: dict[tuple[str, str], list[Any]] = {}

        for rec in records:
            uuid_self = rec.get("uuid")
            pid = rec.get("id")
            if not uuid_self or not pid:
                continue
            by_uuid[uuid_self] = (pid, rec.get("name"))
            for partner_uuid, entry in (
                rec.get("props", {}).get("possible_duplicates", {}).items()
            ):
                side_entries[(uuid_self, str(partner_uuid))] = list(entry)

        edges: set[tuple[str, str]] = {
            (u_self, u_partner) if u_self <= u_partner else (u_partner, u_self)
            for u_self, u_partner in side_entries
        }

        out: list[dict[str, Any]] = []
        for a_uuid, b_uuid in edges:
            a = by_uuid.get(a_uuid)
            b = by_uuid.get(b_uuid)
            if a is None or b is None:
                self.logger.warning(
                    "list_duplicate_pairs: one-sided possible_duplicates "
                    "reference for pair (%s, %s); partner record missing "
                    "from the cross-ref scan — investigate possible "
                    "deletion or partial write",
                    a_uuid,
                    b_uuid,
                )
                continue
            entry_a = side_entries.get((a_uuid, b_uuid))
            entry_b = side_entries.get((b_uuid, a_uuid))
            if entry_a is None or entry_b is None:
                self.logger.warning(
                    "list_duplicate_pairs: one-sided possible_duplicates "
                    "entry for pair (%s, %s); reverse entry missing — "
                    "investigate possible partial write",
                    a_uuid,
                    b_uuid,
                )
                continue
            if entry_a != entry_b:
                self.logger.warning(
                    "list_duplicate_pairs: score mismatch on pair "
                    "(%s, %s): a=%s, b=%s; using higher score",
                    a_uuid,
                    b_uuid,
                    entry_a,
                    entry_b,
                )
            score_a, method_a = entry_a
            score_b, method_b = entry_b
            score, method = (
                (score_a, method_a) if score_a >= score_b else (score_b, method_b)
            )
            a_pid, a_name = a
            b_pid, b_name = b
            out.append({
                "score": score,
                "score_method": method,
                "a_uuid": a_uuid,
                "a_pid": a_pid,
                "a_name": a_name,
                "b_uuid": b_uuid,
                "b_pid": b_pid,
                "b_name": b_name,
            })

        out.sort(key=lambda r: (-r["score"], r["a_pid"], r["b_pid"]))
        return out

    def list_dismissed_duplicate_pairs(
        self,
        *,
        identity: Identity | None = None,
    ) -> list[dict[str, Any]]:
        """Return all Names record pairs currently marked as not-duplicates.

        Scans the Names index for records whose
        `props.dismissed_duplicates` list is non-empty, then emits
        one row per unique pair. Because dismissal is two-sided, both
        sides should appear in the scan; the method logs (and skips)
        any one-sided references it finds, which usually indicates a
        partial-failure state worth investigating.

        Args:
            identity: Optional Invenio identity. Defaults to
                `system_identity`.

        Returns:
            A list of dicts, each shaped::

                {
                    "a_uuid": "...",
                    "a_pid": "kc|jdoe",
                    "a_name": "Doe, John",
                    "b_uuid": "...",
                    "b_pid": "0000-0001-...",
                    "b_name": "Doe, Jonathan",
                }
        """
        service = self.names_service
        identity = identity or system_identity

        records_by_uuid: dict[str, dict[str, Any]] = {}
        edges: set[tuple[str, str]] = set()

        try:
            scan_results = service.scan(identity=identity)
        except Exception:
            self.logger.warning(
                "list_dismissed_duplicate_pairs: scan failed",
                exc_info=True,
            )
            return []

        for hit in scan_results.hits:
            rec = hit if isinstance(hit, dict) else hit.to_dict()
            dismissed = rec.get("props", {}).get("dismissed_duplicates", [])
            if not dismissed:
                continue
            pid = rec.get("id")
            if not pid:
                continue
            item = self._read_existing(identity, pid)
            if item is None:
                continue
            uuid_self = self._record_uuid(item)
            records_by_uuid[uuid_self] = {
                "uuid": uuid_self,
                "pid": pid,
                "name": rec.get("name"),
            }
            for partner_uuid in dismissed:
                pu = str(partner_uuid)
                edges.add((uuid_self, pu) if uuid_self <= pu else (pu, uuid_self))

        out: list[dict[str, Any]] = []
        for a_uuid, b_uuid in sorted(edges):
            a = records_by_uuid.get(a_uuid)
            b = records_by_uuid.get(b_uuid)
            if not a or not b:
                self.logger.warning(
                    "list_dismissed_duplicate_pairs: one-sided "
                    "dismissed reference for pair (%s, %s); other "
                    "side has no matching entry — investigate "
                    "possible partial dismissal",
                    a_uuid,
                    b_uuid,
                )
                continue
            out.append({
                "a_uuid": a["uuid"],
                "a_pid": a["pid"],
                "a_name": a["name"],
                "b_uuid": b["uuid"],
                "b_pid": b["pid"],
                "b_name": b["name"],
            })
        return out
