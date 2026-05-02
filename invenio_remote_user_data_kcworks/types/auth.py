"""Type definitions for OAuth/CILogon account-resolution payloads.

Built by `CILogonHelpers.build_account_info` and broker
`BrokerHelpers.process_broker_payload`, then passed to
`CILogonHelpers.get_user_from_account_info` to resolve or create the
local `User` row that backs an authenticated remote identity.
"""

from typing import NotRequired, Required, TypedDict

from pydantic import BaseModel, ConfigDict


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


class AccountInfoProfileDict(TypedDict):
    """Profile fragment under `account_info.user.profile`.

    Deprecated
    """

    identifier_orcid: str
    identifier_kc_username: str


class AccountInfoUserDict(TypedDict):
    """User fragment under `account_info.user`.

    Deprecated
    """

    email: str
    profile: AccountInfoProfileDict


class AccountInfoDict(TypedDict, total=False):
    """OAuth/CILogon account payload for user resolution and linking.

    Built by `CILogonHelpers.build_account_info` and broker
    `BrokerHelpers.process_broker_payload`, then passed to
    `CILogonHelpers.get_user_from_account_info`.

    Deprecated
    """

    external_id: Required[str]
    external_method: Required[str]
    user: NotRequired[AccountInfoUserDict]
