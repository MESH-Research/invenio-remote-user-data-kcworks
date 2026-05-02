"""Type definitions for local user-update payloads.

`TypedDict` shapes used by `update_local_user_data` and friends to
carry normalized profile/account changes between the calculation step
and the actual `User` write. Distinct from the over-the-wire
Profiles API models in `types.profiles_api`.
"""

from typing import Any, TypedDict


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

    Same shape as `UserProfileUpdateDict` but all fields are
    required.
    """

    active: bool
    username: str
    email: str
    preferences: dict[str, Any]
    user_profile: UserProfileUpdateDict


class UserChangesDict(TypedDict, total=False):
    """Typed dict for sparse user-change payload.

    Same shape as `CalculatedUserDataDict` but all fields are optional.
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
