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
        """Initialize the broker-token-missing error."""
        message_fragment = message or "Missing broker_token parameter"
        self.message = (
            app.config.get("REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_FAILURE")
            or "{message}"
        ).format(message=message_fragment)
        self.header = header or "We couldn't log you in"
        super().__init__(self.message)


class BrokerTokenDecryptionError(Exception):
    """Exception raised if the login broker token decryption fails."""

    def __init__(self, message=None, header=None):
        """Initialize the broker-token-decryption error."""
        message_fragment = message or "Invalid broker_token"
        self.message = (
            app.config.get("REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_FAILURE")
            or "{message}"
        ).format(message=message_fragment)
        self.header = header or "We couldn't log you in"
        super().__init__(self.message)


class BrokerPayloadExpiredError(Exception):
    """Exception raised if the broker payload has expired."""

    def __init__(self, message=None, header=None):
        """Initialize the broker-payload-expired error."""
        message_fragment = message or "Expired broker payload"
        self.message = (
            app.config.get("REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_FAILURE")
            or "{message}"
        ).format(message=message_fragment)
        self.header = header or "We couldn't log you in"
        super().__init__(self.message)


class BrokerExpiryValueError(Exception):
    """Exception raised if the broker payload expiry period is unreadable."""

    def __init__(self, message=None, header=None):
        """Initialize the broker-expiry-value error."""
        message_fragment = message or "Invalid broker payload expiry value"
        self.message = (
            app.config.get("REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_FAILURE")
            or "{message}"
        ).format(message=message_fragment)
        self.header = header or "We couldn't log you in"
        super().__init__(self.message)


class BrokerNonceValidationError(Exception):
    """Exception raised if the broker nonce validation fails."""

    def __init__(self, message=None, header=None):
        """Initialize the broker-nonce-validation error."""
        message_fragment = message or "Nonce validation failed"
        self.message = (
            app.config.get("REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_FAILURE")
            or "{message}"
        ).format(message=message_fragment)
        self.header = header or "We couldn't log you in"
        super().__init__(self.message)


class BrokerPayloadProcessingError(Exception):
    """Exception raised if the broker payload can't be processed."""

    def __init__(self, message=None, header=None):
        """Initialize the broker-payload-processing error."""
        message_fragment = message or "Problem processing broker payload"
        self.message = (
            app.config.get("REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_FAILURE")
            or "{message}"
        ).format(message=message_fragment)
        self.header = header or "We couldn't log you in"
        super().__init__(self.message)


class NoIDPFoundError(Exception):
    """Exception raised for errors in the input."""

    def __init__(self, message="No IDP found for user"):
        """Initialize the no-IDP-found error."""
        self.message = message
        self.header = None
        super().__init__(self.message)


class LocalUserNotFoundError(Exception):
    """Raised when no Invenio user row exists for the given local user id."""

    def __init__(self, message: str | None = None):
        """Create error; `message` defaults to a generic not-found text."""
        self.message = message or "No local Invenio user for the given id"
        self.header = None
        super().__init__(self.message)


class StateTokenInvalid(Exception):
    """Exception raised if oauth state token validation fails."""

    def __init__(self, description=None, header=None):
        """Initialize the invalid-state-token error."""
        description_fragment = description or "OAuth state token validation failed."
        self.description = (
            app.config.get("REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_INVALID_STATE")
            or "{message}"
        ).format(message=description_fragment)
        self.header = header or "We couldn't log you in"
        super().__init__(self.description)


class IDTokenInvalid(Exception):
    """Exception raised if OAuth ID token validation fails."""

    def __init__(self, message=None, header=None):
        """Initialize the invalid-ID-token error."""
        message_fragment = message or "Returned OAuth id token validation failed."
        self.message = (
            app.config.get("REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_INVALID_TOKEN")
            or "{message}"
        ).format(message=message_fragment)
        self.header = header or "We couldn't log you in"
        super().__init__(self.message)


class UserCreationFailed(Exception):
    """Exception raised if the local user cannot be created."""

    def __init__(self, message=None, header=None):
        """Initialize the user-creation-failed error."""
        message_fragment = message or "Could not create a new KCWorks user to log in."
        self.message = (
            app.config.get("REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_INVALID_TOKEN")
            or "{message}"
        ).format(message=message_fragment)
        self.header = header or "We couldn't log you in"
        super().__init__(self.message)


class UserDataRequestFailed(Exception):
    """Exception raised if the user-data API request fails."""

    def __init__(self, message=None, header=None):
        """Initialize the user-data-request-failed error."""
        message_fragment = (
            message or "Connection with the user data API endpoint failed."
        )
        self.message = (
            app.config.get("REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_CONNECTION")
            or "{message}"
        ).format(message=message_fragment)
        self.header = header or "We couldn't log you in"
        super().__init__(self.message)


class UserDataRequestTimeout(Exception):
    """Exception raised if the user-data API request times out."""

    def __init__(self, message=None, header=None):
        """Initialize the user-data-request-timeout error."""
        message_fragment = message or "Request to the user data API endpoint timed out."
        self.message = message or (
            app.config.get("REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_TIMEOUT")
            or "{message}"
        ).format(message=message_fragment)
        self.header = header or "We couldn't log you in"
        super().__init__(self.message)
