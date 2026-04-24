"""Type definitions for Names vocabulary payloads.

Locally constructed `TypedDict` shapes for create/update calls to the
upstream Names vocabulary service. Authoritative validation is
delegated to `invenio_vocabularies.contrib.names.schema.NameSchema`,
which the service invokes on every load; these types only document
shape and give static checkers something to enforce at construction
sites.
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
    """

    kcworks_user_id: str
    kc_username: str
    orcid: str
    display_name: str
    name_parts: dict[str, str]
    source: str  # Why a `kcworks-cited` record was materialized


class NamePayloadDict(TypedDict, total=False):
    """Dict for creating/updating one name vocabulary item.

    Corresponds to the shape accepted by the NameSchema validator in
    `invenio_vocabularies.contrib.names.schema.NameSchema`. We don't
    want the overhead of Pydantic validation when assembling this payload
    because it would duplicate the Marshmallow schema validation performed
    by the NamesService when a name record item is created/updated.

    The NameSchema will enforce the presence of either `name` or both
    `given_name` and `family_name`. But we don't try to mirror that
    constraint in the names sync service.
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
