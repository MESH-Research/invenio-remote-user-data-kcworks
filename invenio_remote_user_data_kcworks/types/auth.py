"""Type definitions for OAuth/CILogon account-resolution payloads."""

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
