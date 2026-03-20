# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Exception classes for invenio-remote-user-data-kcworks."""

from flask import current_app as app


class BrokerTokenMissingError(Exception):
    """Exception raised if the login broker token is missing."""

    def __init__(self, message=None, header=None):
        message_fragment = message or "Missing broker_token parameter"
        self.message = app.config.get(
            "REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_FAILURE"
        ).format(message=message_fragment)
        self.header = header or "We couldn't log you in"
        super().__init__(self.message)


class BrokerTokenDecryptionError(Exception):
    """Exception raised if the login broker token decryption fails."""

    def __init__(self, message=None, header=None):
        message_fragment = message or "Invalid broker_token"
        self.message = app.config.get(
            "REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_FAILURE"
        ).format(message=message_fragment)
        self.header = header or "We couldn't log you in"
        super().__init__(self.message)


class BrokerPayloadExpiredError(Exception):
    """Exception raised if the broker payload has expired."""

    def __init__(self, message=None, header=None):
        message_fragment = message or "Expired broker payload"
        self.message = app.config.get(
            "REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_FAILURE"
        ).format(message=message_fragment)
        self.header = header or "We couldn't log you in"
        super().__init__(self.message)


class BrokerExpiryValueError(Exception):
    """Exception raised if the broker payload expiry period is unreadable."""

    def __init__(self, message=None, header=None):
        message_fragment = message or "Invalid broker payload expiry value"
        self.message = app.config.get(
            "REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_FAILURE"
        ).format(message=message_fragment)
        self.header = header or "We couldn't log you in"
        super().__init__(self.message)


class BrokerNonceValidationError(Exception):
    """Exception raised if the broker nonce validation fails."""

    def __init__(self, message=None, header=None):
        message_fragment = message or "Nonce validation failed"
        self.message = app.config.get(
            "REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_FAILURE"
        ).format(message=message_fragment)
        self.header = header or "We couldn't log you in"
        super().__init__(self.message)


class BrokerPayloadProcessingError(Exception):
    """Exception raised if the broker payload can't be processed."""

    def __init__(self, message=None, header=None):
        message_fragment = message or "Problem processing broker payload"
        self.message = app.config.get(
            "REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_FAILURE"
        ).format(message=message_fragment)
        self.header = header or "We couldn't log you in"
        super().__init__(self.message)


class NoIDPFoundError(Exception):
    """Exception raised for errors in the input."""

    def __init__(self, message="No IDP found for user"):
        self.message = message
        self.header = None
        super().__init__(self.message)


class StateTokenInvalid(Exception):
    """Exception raised if oauth state token validation fails."""

    def __init__(self, description=None, header=None):
        description_fragment = description or "OAuth state token validation failed."
        self.description = app.config.get(
            "REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_INVALID_STATE"
        ).format(message=description_fragment)
        self.header = header or "We couldn't log you in"
        super().__init__(self.description)


class IDTokenInvalid(Exception):
    def __init__(self, message=None, header=None):
        message_fragment = message or "Returned OAuth id token validation failed."
        self.message = app.config.get(
            "REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_INVALID_TOKEN"
        ).format(message=message_fragment)
        self.header = header or "We couldn't log you in"
        super().__init__(self.message)


class UserDataRequestFailed(Exception):
    def __init__(self, message=None, header=None):
        message_fragment = (
            message or "Connection with the user data API endpoint failed."
        )
        self.message = app.config.get(
            "REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_CONNECTION"
        ).format(message=message_fragment)
        self.header = header or "We couldn't log you in"
        super().__init__(self.message)


class UserDataRequestTimeout(Exception):
    def __init__(self, message=None, header=None):
        message_fragment = message or "Request to the user data API endpoint timed out."
        self.message = message or app.config.get(
            "REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_TIMEOUT"
        ).format(message=message_fragment)
        self.header = header or "We couldn't log you in"
        super().__init__(self.message)
