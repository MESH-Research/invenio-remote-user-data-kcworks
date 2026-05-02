"""Pydantic models for Profiles API wire data.

Used to parse JSON payloads received from the upstream Profiles API
(user profile fetches, paginated profile lists, logout requests).
Distinct from the project's *internal* user-profile types in
`types.users`, which describe locally constructed update payloads.
"""

from pydantic import BaseModel, HttpUrl


class AcademicInterest(BaseModel):
    """AcademicInterest is a Pydantic model of data associated with a user."""

    id: int | None = None
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
    first_name: str | None
    last_name: str | None
    institutional_affiliation: str | None
    orcid: str | None
    academic_interests: list[AcademicInterest] | None = None
    groups: list[Group] | None = None
    avatar: str | None = None
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
