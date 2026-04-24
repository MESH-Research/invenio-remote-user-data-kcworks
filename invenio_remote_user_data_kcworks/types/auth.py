"""Type definitions for OAuth/CILogon account-resolution payloads.

Built by `CILogonHelpers.build_account_info` and broker
`BrokerHelpers.process_broker_payload`, then passed to
`CILogonHelpers.get_user_from_account_info` to resolve or create the
local `User` row that backs an authenticated remote identity.
"""

from typing import NotRequired, Required, TypedDict


class AccountInfoProfileDict(TypedDict):
    """Profile fragment under `account_info.user.profile`."""

    identifier_orcid: str
    identifier_kc_username: str


class AccountInfoUserDict(TypedDict):
    """User fragment under `account_info.user`."""

    email: str
    profile: AccountInfoProfileDict


class AccountInfoDict(TypedDict, total=False):
    """OAuth/CILogon account payload for user resolution and linking.

    Built by `CILogonHelpers.build_account_info` and broker
    `BrokerHelpers.process_broker_payload`, then passed to
    `CILogonHelpers.get_user_from_account_info`.
    """

    external_id: Required[str]
    external_method: Required[str]
    user: NotRequired[AccountInfoUserDict]
