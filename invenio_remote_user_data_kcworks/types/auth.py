# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

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
