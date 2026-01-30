#
# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Exception classes for invenio-remote-user-data-kcworks."""


class NoIDPFoundError(Exception):
    """Exception raised for errors in the input."""

    def __init__(self, message="No IDP found for user"):
        self.message = message
        super().__init__(self.message)


class StateTokenInvalid(Exception):
    """Exception raised if oauth state token validation fails."""

    def __init__(self, description="OAuth state token validation failed."):
        self.description = description
        super().__init__(self.description)


class IDTokenInvalid(Exception):
    def __init__(self, message="Returned JWT id_token is not valid."):
        self.message = message
        super().__init__(self.message)


class UserDataRequestFailed(Exception):
    def __init__(
        self, message="Request to retrieve user data from profiles app failed."
    ):
        self.message = message
        super().__init__(self.message)


class UserDataRequestTimeout(Exception):
    def __init__(
        self, message="Request to retrieve user data from profiles app timed out."
    ):
        self.message = message
        super().__init__(self.message)
