"""Pydantic data models for remote-user-data payloads."""

from typing import Any, NotRequired, Required, TypedDict

from pydantic import BaseModel, HttpUrl


class AcademicInterest(BaseModel):
    """AcademicInterest is a Pydantic model of data associated with a user."""

    id: int
    text: str


class Group(BaseModel):
    """Group model representing a user's group membership."""

    id: int
    group_name: str | None = None
    role: str
    url: HttpUrl | None = None


class Profile(BaseModel):
    """Profile is a Pydantic model of a user."""

    username: str
    name: str
    email: str
    first_name: str
    last_name: str
    institutional_affiliation: str
    orcid: str
    academic_interests: list[AcademicInterest] | None = None
    groups: list[Group]
    url: HttpUrl | None = None
    is_superadmin: bool = False


class SubData(BaseModel):
    """SubData is a Pydantic model for the user profile."""

    sub: str
    profile: Profile


class Meta(BaseModel):
    """Meta is a Pydantic model that represents the metadata of the response."""

    authorized: bool


class APIResponse(BaseModel):
    """APIResponse is a Pydantic model that represents the API endpoint."""

    data: list[SubData]
    meta: Meta
    next: str | None
    previous: str | None


class LogoutRequest(BaseModel):
    """A Pydantic model representing the signal to be sent for global logout."""

    user_name: str
    user_agent: str


class AccountInfoProfileDict(TypedDict):
    """Profile fragment under account_info.user.profile."""

    identifier_orcid: str
    identifier_kc_username: str


class AccountInfoUserDict(TypedDict):
    """User fragment under account_info.user."""

    email: str
    profile: AccountInfoProfileDict


class AccountInfoDict(TypedDict, total=False):
    """OAuth/CILogon account payload for user resolution and linking.

    Built by :meth:`CILogonHelpers.build_account_info` and broker
    :meth:`BrokerHelpers.process_broker_payload`, then passed to
    :meth:`CILogonHelpers.get_user_from_account_info`.
    """

    external_id: Required[str]
    external_method: Required[str]
    user: NotRequired[AccountInfoUserDict]


class UserProfileUpdateDict(TypedDict, total=False):
    """Typed dict for normalized/sparse user_profile update values."""

    full_name: str
    name_parts: str
    affiliations: str
    identifier_orcid: str
    identifier_kc_username: str
    identifier_email: str


class CalculatedUserDataDict(TypedDict):
    """Typed dict for full normalized user update payload.

    Same shape as UserProfileUpdateDict but all fields are
    required.
    """

    active: bool
    username: str
    email: str
    preferences: dict[str, Any]
    user_profile: UserProfileUpdateDict


class UserChangesDict(TypedDict, total=False):
    """Typed dict for sparse user-change payload.

    Same shape as CalculatedUserDataDict but all fields are optional.
    """

    active: bool
    username: str
    email: str
    preferences: dict[str, Any]
    user_profile: UserProfileUpdateDict


class GroupChangesDict(TypedDict):
    """Typed dict for lists of changed and unchanged groups.

    All strings in the lists should be group role names.
    """

    dropped_groups: list[str]
    added_groups: list[str]
    unchanged_groups: list[str]


class UpdateLocalUserDataResultDict(TypedDict):
    """Typed dict result shape for local user/group updates."""

    user: UserChangesDict
    groups: list[str]
