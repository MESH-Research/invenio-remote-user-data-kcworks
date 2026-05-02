"""Pydantic data models for remote-user-data payloads."""

from typing import Any, TypedDict

from pydantic import BaseModel, ConfigDict, HttpUrl


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


class AccountInfo(BaseModel):
    """OAuth/CILogon account payload for user resolution and linking.

    Built by BrokerDecodedToken.to_account_info, then passed to
    CILogonHelpers.get_user_from_account_info.
    """

    model_config = ConfigDict(extra="forbid")

    external_id: str
    external_method: str
    email: str
    orcid: str | None = None
    kc_username: str


class BrokerDecodedUserinfo(BaseModel):
    """Nested userinfo object from the Profiles broker token (observed wire shape)."""

    model_config = ConfigDict(extra="ignore")

    sub: str
    email: str
    name: str
    idp_name: str
    orcid: str | None = None


class BrokerDecodedToken(BaseModel):
    """Decrypted Profiles broker token (observed wire shape only).

    Required incoming: userinfo, final_redirect, kc_username, primary_email,
    nonce, iat, exp. Optional: other_emails. Unknown keys are ignored
    (extra="ignore").
    """

    model_config = ConfigDict(extra="ignore")

    userinfo: BrokerDecodedUserinfo
    final_redirect: str
    kc_username: str
    primary_email: str
    other_emails: list[str] | None = None
    nonce: str
    iat: float | int
    exp: float | int

    @property
    def resolved_email(self) -> str:
        """Preferred email: primary_email, falling back to userinfo.email."""
        return self.primary_email or self.userinfo.email

    def to_account_info(self):
        """Build an AccountInfo model based on this data"""
        info = AccountInfo(
            external_id=self.userinfo.sub,
            email=self.resolved_email,
            orcid=self.userinfo.orcid,
            kc_username=self.kc_username,
            external_method="cilogon",
        )
        return info


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
