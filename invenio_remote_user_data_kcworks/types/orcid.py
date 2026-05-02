"""Pydantic models for ORCID Public API JSON responses.

Covers the two endpoints this package consumes directly:

- `GET /v3.0/expanded-search/?q=...` -> `OrcidExpandedSearchResponse`
- `GET /v3.0/{orcid_id}/record` -> `OrcidRecord`

Wire keys are hyphenated; aliases preserve them while exposing
Pythonic snake_case attribute names. `populate_by_name=True` lets
callers construct instances with either form. `extra="ignore"` keeps
us tolerant of new ORCID fields (and of the long tail of fields we
do not currently consume on the per-record fetch).

Validation policy: a result is only useful to us if it carries an
ORCID iD plus at least one usable display form, namely a `credit-name`
or both `given-names` and `family-name(s)`. Both `OrcidExpandedResult`
and `OrcidRecord` enforce this and will raise `ValidationError` on
construction otherwise. Callers should treat such errors as a signal
to drop the result (search) or skip insertion (per-record fetch).
"""

from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

_BASE_CONFIG = ConfigDict(
    extra="ignore",
    populate_by_name=True,
)


def _unwrap_value(value: Any) -> Any:
    """Pull `.value` out of ORCID's `{"value": "..."}` leaf wrappers.

    Many leaf strings on the per-record fetch are wrapped as
    `{"value": "..."}` blocks. The `OrcidName` field validators use
    this to flatten them so consumers see plain strings.

    Args:
        value: The raw field value as received from ORCID. Either an
            already-flat scalar or a `{"value": ...}` wrapper dict.

    Returns:
        The unwrapped inner value when `value` is a wrapper dict, the
        wrapper's `.value` (or `None` if absent), or the input
        unchanged otherwise.
    """
    if isinstance(value, dict):
        return value.get("value")
    return value


# ---------------------------------------------------------------------
# Expanded search (/v3.0/expanded-search/?q=...)
# ---------------------------------------------------------------------


class OrcidExpandedResult(BaseModel):
    """One hit from the expanded-search endpoint.

    Validates that the result is minimally usable: an ORCID iD plus
    either `credit-name` or both `given-names` and `family-names`.
    """

    model_config = _BASE_CONFIG

    orcid_id: str = Field(alias="orcid-id")
    given_names: str | None = Field(default=None, alias="given-names")
    family_names: str | None = Field(default=None, alias="family-names")
    credit_name: str | None = Field(default=None, alias="credit-name")
    institution_name: list[str] = Field(
        default_factory=list, alias="institution-name"
    )
    other_name: list[str] = Field(default_factory=list, alias="other-name")
    email: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _require_usable_name(self) -> "OrcidExpandedResult":
        if not self.credit_name and not (
            self.given_names and self.family_names
        ):
            raise ValueError(
                "ORCID expanded-search result missing both credit-name "
                "and a complete given-names/family-names pair"
            )
        return self


class OrcidExpandedSearchResponse(BaseModel):
    """Full envelope returned by the expanded-search endpoint."""

    model_config = _BASE_CONFIG

    expanded_result: list[OrcidExpandedResult] = Field(
        default_factory=list, alias="expanded-result"
    )
    num_found: int = Field(alias="num-found")


# ---------------------------------------------------------------------
# Per-record fetch (/v3.0/{orcid_id}/record)
# ---------------------------------------------------------------------


class OrcidName(BaseModel):
    """The `person.name` block on the full record.

    Each leaf is wrapped on the wire as `{"value": "..."}`; the
    field validators flatten this so attributes are plain strings.
    """

    model_config = _BASE_CONFIG

    given_names: str | None = Field(default=None, alias="given-names")
    family_name: str | None = Field(default=None, alias="family-name")
    credit_name: str | None = Field(default=None, alias="credit-name")

    _unwrap = field_validator(
        "given_names", "family_name", "credit_name", mode="before"
    )(_unwrap_value)


class OrcidPerson(BaseModel):
    """The `person` block on the full record."""

    model_config = _BASE_CONFIG

    name: OrcidName | None = None


class OrcidIdentifierBlock(BaseModel):
    """The `orcid-identifier` block on the full record.

    `path` carries the bare ORCID iD (e.g. `"0000-0001-2345-6789"`).
    """

    model_config = _BASE_CONFIG

    path: str


class OrcidDisambiguatedOrg(BaseModel):
    """The `disambiguated-organization` block on an organization."""

    model_config = _BASE_CONFIG

    disambiguated_organization_identifier: str | None = Field(
        default=None, alias="disambiguated-organization-identifier"
    )
    disambiguation_source: str | None = Field(
        default=None, alias="disambiguation-source"
    )


class OrcidOrganization(BaseModel):
    """The `organization` block on an employment summary."""

    model_config = _BASE_CONFIG

    name: str
    disambiguated_organization: OrcidDisambiguatedOrg | None = Field(
        default=None, alias="disambiguated-organization"
    )


class OrcidEmploymentSummary(BaseModel):
    """One `employment-summary` block under an affiliation-group entry.

    `end_date` is left loosely typed: ORCID returns a structured
    year/month/day block when the employment has ended, and `null`
    otherwise. Consumers only need to test truthiness to decide
    whether the affiliation is current (mirroring the upstream
    `OrcidTransformer` behavior of skipping terminated employments).
    """

    model_config = _BASE_CONFIG

    end_date: Any | None = Field(default=None, alias="end-date")
    organization: OrcidOrganization


class OrcidAffiliationGroupEntry(BaseModel):
    """One entry in `activities-summary.employments.affiliation-group`."""

    model_config = _BASE_CONFIG

    employment_summary: OrcidEmploymentSummary = Field(
        alias="employment-summary"
    )


class OrcidEmployments(BaseModel):
    """The `employments` block under `activities-summary`."""

    model_config = _BASE_CONFIG

    affiliation_group: list[OrcidAffiliationGroupEntry] = Field(
        default_factory=list, alias="affiliation-group"
    )

    @field_validator("affiliation_group", mode="before")
    @classmethod
    def _coerce_to_list(cls, value: Any) -> Any:
        # ORCID's JSON API normalizes single-child collections to a
        # one-element list, but the XML-derived dict path (used by
        # the upstream harvester) wraps a single child as a bare
        # dict. We accept both for safety.
        if isinstance(value, dict):
            return [value]
        return value


class OrcidActivitiesSummary(BaseModel):
    """The `activities-summary` block on the full record."""

    model_config = _BASE_CONFIG

    employments: OrcidEmployments | None = None


class OrcidRecord(BaseModel):
    """Full record returned by `/v3.0/{orcid_id}/record`.

    Models only the slice this package consumes (ORCID iD, person
    name block, current employments). Validation requires a bare
    ORCID iD plus either `credit-name` or both `given-names` and
    `family-name` on the person's name block.
    """

    model_config = _BASE_CONFIG

    orcid_identifier: OrcidIdentifierBlock = Field(alias="orcid-identifier")
    person: OrcidPerson | None = None
    activities_summary: OrcidActivitiesSummary | None = Field(
        default=None, alias="activities-summary"
    )

    @model_validator(mode="after")
    def _require_usable_name(self) -> "OrcidRecord":
        name = self.person.name if self.person else None
        if not name or (
            not name.credit_name
            and not (name.given_names and name.family_name)
        ):
            raise ValueError(
                "ORCID record missing both credit-name and a complete "
                "given-names/family-name pair"
            )
        return self

    @property
    def orcid_id(self) -> str:
        """Bare ORCID iD convenience accessor."""
        return self.orcid_identifier.path
