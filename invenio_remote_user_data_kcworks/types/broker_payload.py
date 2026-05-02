# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Decrypted Profiles broker token — same shapes as BrokerDecoded* in KC Works."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from .auth import AccountInfo


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
