"""Type definitions for Names vocabulary records.

`TypedDict` shapes used both for create/update *payloads* sent to the
upstream Names vocabulary service and for the *record dicts* read
back from it. Authoritative validation is delegated to
`invenio_vocabularies.contrib.names.schema.NameSchema`, which the
service invokes on every load; these types only document shape and
give static checkers something to enforce at construction and
consumption sites.

Read-side records returned by the service also carry system fields
(`created`, `updated`, `revision_id`, `pid`, `links`, etc.) that this
package does not consume and so does not model here.
"""

from typing import TypedDict

from ..config import KCNamesTag


class NameIdentifierDict(TypedDict):
    """Single dict for an identifier in a names vocabulary item.

    Field names mirror `marshmallow_utils.schemas.IdentifierSchema`,
    which the upstream `NameSchema` nests under `identifiers`.
    """

    scheme: str
    identifier: str


class NameAffiliationDict(TypedDict, total=False):
    """Single dict for an affiliation in a names vocabulary item."""

    id: str
    name: str


class NamePropsDict(TypedDict, total=False):
    """Standard props stored under the Names record's `props` field.

    Rule of thumb: identifier-shaped data (anything carrying a
    registered scheme such as `orcid`, `kc_username`, `email`, `isni`,
    etc.) belongs in the record's `identifiers` list, not here.
    `props` is reserved for derived display state (`display_name`,
    `name_parts`), internal references that have no public identifier
    scheme (`kcworks_user_id`), and operational metadata (`source`).

    `display_name` is necessary because `NameSchema` overwrites the
    payload's `name` field with a naive `"family_name, given_name"`
    composition for personal names whenever both parts are present,
    discarding any richer form (particles, suffixes, non-Western name
    orderings, etc.). The rich form composed by `utils.names`
    helpers is preserved here.

    `name_parts` mirrors the structured parts dict consumed by
    `utils.names.get_full_name` / `get_full_name_inverted`. Note that
    it is stored here as a real nested dict, not as a JSON string the
    way `user_profile["name_parts"]` is stored on KC users; translate
    on the way in (`json.loads`) when seeding from the user profile.

    `dismissed_duplicates` is a list of Names record UUIDs that an
    operator has explicitly marked as not-a-duplicate of this record
    via `NamesSyncService.dismiss_duplicate_pair()`. The dedup sweep
    consults both sides of each candidate pair and skips any pair
    where either side carries the other's UUID, so a one-time dismissal
    suppresses re-flagging on every subsequent run.

    `possible_duplicates` is a mapping from another Names record's
    UUID to a 2-element list `[score, score_method]` describing the
    best (highest-scoring) duplicate candidacy the periodic dedup
    sweep has found between this record and that one. The list shape
    is chosen because JSON has no tuple type: persisting a Python
    tuple round-trips through OpenSearch as a list, so we use a list
    end-to-end. `score` is a `float`; `score_method` is one of the
    `family_*+given_*` strategy codes documented on
    `NamesSyncService.find_duplicate_candidates`. Cross-references are
    symmetric: each side carries an entry for the other.

    `family_token` is a coarse, normalized form of `family_name`
    (NFKD asciifold + lowercased + punctuation stripped + whitespace
    collapsed) populated at write time by `NamesSyncService`. It is
    the canonical single-valued display form used for reporting; the
    actual aggregation key is `family_part_tokens`. Records that
    pre-date this field (or that are written by upstream paths we do
    not control) simply do not appear in any bucket.

    `family_part_tokens` is the multi-valued bucket index used by the
    token pass of the periodic dedup sweep. It contains the full
    normalized family form (element 0) plus each constituent piece,
    treating both whitespace and hyphens as separators. So
    `García López` and `García-López` both index as
    `["garcia lopez", "garcia", "lopez"]` and cluster with single-piece
    `García` (`["garcia"]`) records via the shared `garcia` bucket.
    `_score_bucket_pairs` then classifies each surviving pair as
    full-family or partial-family match by comparing the bucket key
    against element 0 of each side, applying `PARTIAL_FAMILY_DISCOUNT`
    to partial matches.

    `family_phonetic_tokens` is the multi-valued bucket index used by
    the phonetic pass of the same sweep. Each piece of the family
    name (split on the same rules as `family_part_tokens`) is encoded
    with Metaphone; the codes are deduped order-preserving. Catches
    spelling variants the token index cannot, e.g. `Smith`/`Smyth`
    (both `SM0`), `OBrien`/`OBrian` (both `OBRN`). `_score_bucket_pairs`
    applies `PHONETIC_FAMILY_DISCOUNT` to scores from this pass.
    """

    kcworks_user_id: str
    display_name: str
    name_parts: dict[str, str]
    source: str  # What triggered insertion of the `kcworks-cited` record
    dismissed_duplicates: list[str]  # Names record UUIDs dismissed by an operator
    possible_duplicates: dict[
        str, list[float | str]
    ]  # other_uuid -> [score: float, score_method: str]
    family_token: str  # Canonical normalized family_name; reporting only
    family_part_tokens: list[str]  # Multi-valued bucket index, token pass
    family_phonetic_tokens: list[str]  # Multi-valued bucket index, phonetic pass


class NamesRecordDict(TypedDict, total=False):
    """Dict for one Names vocabulary item, used for both reads and writes.

    Corresponds to the shape accepted by the NameSchema validator in
    `invenio_vocabularies.contrib.names.schema.NameSchema`. We don't
    want the overhead of Pydantic validation when assembling this payload
    because it would duplicate the Marshmallow schema validation performed
    by the NamesService when a name record item is created/updated.

    The NameSchema will enforce the presence of either `name` or both
    `given_name` and `family_name`. But we don't try to mirror that
    constraint here.

    Also used as a read-side type when consuming records returned by
    the service. Read-side records additionally carry system fields
    (`created`, `updated`, `revision_id`, `pid`, `links`) that this
    package does not consume; they are intentionally omitted here.
    Records authored by the upstream
    `invenio_vocabularies.contrib.names.datastreams.OrcidTransformer`
    will populate only `id`, `given_name`, `family_name`, and
    `identifiers` (a single `orcid`-scheme entry) plus `affiliations`,
    leaving `name`, `props`, and `tags` empty.
    """

    id: str  # PID on create, ignored on update
    name: str  # Single string with full name in Last, First inverted form
    given_name: str
    family_name: str
    internal_id: str
    identifiers: list[NameIdentifierDict]
    affiliations: list[NameAffiliationDict]
    props: NamePropsDict
    tags: list[KCNamesTag]
    uuid: str
    # `uuid` is the Names DB row's primary-key UUID, written into the
    # OpenSearch source by the Names `SearchDumper`. It is therefore
    # present on records pulled out of indexed search hits but absent
    # from records returned by `service.read().to_dict()` (which goes
    # through `NameSchema`, which does not declare `uuid`). Do NOT
    # confuse with `opensearch_dsl.response.hit.HitMeta.id`, which is
    # the OpenSearch document id and only happens to equal the DB UUID
    # by current dumper convention.
