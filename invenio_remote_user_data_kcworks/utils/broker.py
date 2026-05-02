# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""SSO broker helpers, token mechanics, and bearer-token extraction."""

import base64
import contextlib
import hashlib
import json
import os
import time

import requests
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Response, request
from flask import current_app as app
from invenio_access.permissions import system_identity
from invenio_accounts.errors import AlreadyLinkedError
from invenio_accounts.models import User
from pydantic import ValidationError

from ..client import UserDataAPIClient
from ..errors import (
    BrokerExpiryValueError,
    BrokerNonceValidationError,
    BrokerPayloadExpiredError,
    BrokerPayloadProcessingError,
    BrokerTokenDecryptionError,
    BrokerTokenMissingError,
    UserDataRequestFailed,
    UserDataRequestTimeout,
)
from ..proxies import current_remote_user_data_service
from ..types.broker_payload import BrokerDecodedToken
from ..types.profiles_api import APIResponse
from .auth import CILogonHelpers


def extract_bearer_token(header_string: str) -> str:
    """Extract the actual bearer token from an Authorization header.

    Returns:
        str: The bearer token.

    Raises:
        ValueError: If the header string is None, malformed, or
          the token itself is empty.
    """
    header_parts = header_string.split(None, 1)
    if not header_string:
        raise ValueError("Authorization header was empty.")
    if len(header_parts) < 2 or header_parts[0] != "Bearer":
        raise ValueError("Authorization header was malformed.")
    token = header_parts[1].strip()
    if not token:
        raise ValueError("Authorization token was empty.")
    else:
        return token


class SecureParamEncoder:
    """Encrypt and encode data for URL transmission."""

    def __init__(self, shared_secret: str):
        """Initialize the SecureParamEncoder.

        Args:
            shared_secret (str): The shared secret used for encryption.
        """
        # Derive a 32-byte key from any length secret
        self.key = hashlib.sha256(shared_secret.encode()).digest()

    def encode(self, data: dict) -> str:
        """Encrypt and encode data.

        Returns:
            str: Encrypted data as a string.
        """
        json_data = json.dumps(data).encode()

        # Generate random IV (init vector)
        iv = os.urandom(16)

        # Pad data to block size
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(json_data) + padder.finalize()

        # Encrypt
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()

        # Combine IV + encrypted data
        result = iv + encrypted
        return base64.urlsafe_b64encode(result).decode()

    def decode(self, encrypted_param: str) -> dict:
        """Decrypt and decode data.

        Returns:
            dict: The decrypted JSON data as a python dictionary.
        """
        data = base64.urlsafe_b64decode(encrypted_param.encode())

        # Extract IV and encrypted data
        iv = data[:16]
        encrypted = data[16:]

        # Decrypt
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted) + decryptor.finalize()

        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        json_data = unpadder.update(padded_data) + unpadder.finalize()

        return json.loads(json_data.decode())


class BrokerHelpers:
    """Helpers for SSO broker authentication."""

    @staticmethod
    def _get_broker_cookie_name() -> str:
        """Retrieve the broker refresh cookie name from config.

        Returns:
            str: The configured refresh cookie name (default '_sso_checked')
        """
        return app.config.get("SSO_BROKER_RETRY_COOKIE_NAME", "_sso_checked")

    @staticmethod
    def _get_broker_cookie_ttl() -> int:
        """Retrieve the broker refresh cookie ttl from config.

        Returns:
            str: The configured refresh cookie ttl in seconds (default 1800)
        """
        return app.config.get("SSO_BROKER_COOKIE_TTL", 1800)

    @staticmethod
    def ready_for_login_broker_check() -> bool:
        """Check whether it's time to check broker for a login again.

        Returns:
            True if it's time to check the login broker for an active
            session, False if it's not.
        """
        cookie_ttl = BrokerHelpers._get_broker_cookie_ttl()
        cookie_name = BrokerHelpers._get_broker_cookie_name()
        cookie_val = request.cookies.get(cookie_name)
        if cookie_val:
            # Server-side TTL validation so we don't rely solely on
            # browser cookie expiry behavior.
            try:
                checked_at = int(float(cookie_val))
                if time.time() - checked_at < int(cookie_ttl):
                    return False
            except (TypeError, ValueError):
                # If the cookie value is unexpected, treat it as expired.
                pass
        return True

    @staticmethod
    def set_broker_refresh_cookie(response) -> Response:
        """Set the broker refresh cookie.

        Returns:
            Response: A Flask Response object with new cookie set.
        """
        cookie_name = BrokerHelpers._get_broker_cookie_name()
        cookie_ttl = BrokerHelpers._get_broker_cookie_ttl()
        response.set_cookie(
            cookie_name,
            str(int(time.time())),
            max_age=cookie_ttl,
            httponly=True,
            secure=True,
            samesite="Lax",  # necessary for Safari & Firefox
        )
        return response

    @staticmethod
    def clear_broker_refresh_cookie(response) -> Response:
        """Delete the broker retry cookie from the current response.

        Returns:
            Response: A Flask Response object with cookie deleted.
        """
        cookie_name = BrokerHelpers._get_broker_cookie_name()
        response.delete_cookie(cookie_name)
        return response

    def _decrypt_broker_token(self, token: str) -> dict:
        """Decrypt an AES-256-CBC broker token using the shared secret.

        Args:
            token: The base64url-encoded encrypted token string.

        Returns:
            The decrypted payload as a dict.

        Raises:
            BrokerTokenDecryptionError: If the token cannot be decrypted or parsed.
        """
        try:
            secret = os.getenv("COMMONS_PROFILES_API_TOKEN")
            if not secret:
                raise BrokerTokenDecryptionError(
                    "COMMONS_PROFILES_API_TOKEN environment variable not set"
                )
            encoder = SecureParamEncoder(secret)
            return encoder.decode(token)

        except Exception as e:
            app.logger.exception("Failed to decrypt broker_token")
            raise BrokerTokenDecryptionError from e

    def _validate_nonce(self, nonce: str) -> bool:
        """Validate a broker nonce via the Profiles microservice.

        Args:
            nonce: The nonce string extracted from the broker token payload.

        Returns:
            True if the nonce is valid, False otherwise.
        """
        verify_url = app.config.get("SSO_BROKER_VERIFY_NONCE_URL")
        if not verify_url:
            app.logger.error("SSO_BROKER_VERIFY_NONCE_URL not configured")
            raise BrokerNonceValidationError

        bearer_token = os.getenv("COMMONS_PROFILES_API_TOKEN")
        if not bearer_token:
            app.logger.error("COMMONS_PROFILES_API_TOKEN not set")
            raise BrokerNonceValidationError

        if not nonce:  # in case it's ""
            app.logger.error("nonce was an empty string")
            raise BrokerNonceValidationError

        timeout = app.config.get("SSO_BROKER_SILENT_LOGIN_TIMEOUT", 3)
        try:
            resp = requests.post(
                verify_url,
                json={"nonce": nonce},
                headers={
                    "Authorization": f"Bearer {bearer_token}",
                    "Content-Type": "application/json",
                },
                timeout=timeout,
            )
            resp.raise_for_status()

            if resp.json().get("valid", False) is True:
                return True
            else:
                app.logger.warning("Broker nonce validation failed")
                raise BrokerNonceValidationError

        except Exception:
            app.logger.exception("Nonce validation request failed")
            raise BrokerNonceValidationError

    def _check_broker_token_age(self, expiration: int | float) -> None:
        """Raise an error if the token has expired.

        Raises:
            BrokerExpiredError if the token has expired
            BrokerExpiryValueError if the token expiry is the wrong type
        """
        try:
            if int(float(expiration)) < int(time.time()):
                raise BrokerPayloadExpiredError
        except (TypeError, ValueError) as e:
            raise BrokerExpiryValueError from e

    def process_broker_payload(self, raw_token: str) -> tuple[User | None, str | None]:
        """Extract user identity, find/create th KCWorks user, and update their data.

        Indirectly raises (through helper functions):
            - BrokerTokenDecryptionError if broker jwt decryption fails
            - BrokerExpiredError if the broker jwt has expired
            - BrokerExpiryValueError if the expiry value is the wrong type
            - BrokerNonceValidationError if nonce validation fails

        Args:
            raw_token: The undecrypted broker token string. Decoded will have the
                required keys: userinfo (sub, email, name, idp_name, optional orcid); final_redirect;
                kc_username; primary_email; nonce; iat; exp.. Optional: other_emails

        Returns:
            A tuple of (user, final_redirect). user None if the payload did not
            contain enough information to identify or create a user.

        Raises:
            BrokerPayloadProcessingError: If the decrypted token fails Pydantic
              validation.
            UserDataRequestFailed: If the user's data could not be retrieved from
              the remote endpoint's response.
            UserDataRequestTimeout: If the request to the remote endpoint times out.
        """
        payload = self._decrypt_broker_token(raw_token)

        try:
            token = BrokerDecodedToken.model_validate(payload)
            app.logger.debug("token is")
            app.logger.debug(payload)
        except ValidationError as e:
            raise BrokerPayloadProcessingError(
                "BrokerHelpers.process_broker_payload: invalid decrypted token"
            ) from e

        self._check_broker_token_age(token.exp)

        self._validate_nonce(token.nonce)

        final_redirect = token.final_redirect
        sub = token.userinfo.sub

        user = CILogonHelpers.get_user_from_account_info(token.to_account_info())
        app.logger.debug(f"user is {user}")
        app.logger.debug(f"sub is {sub}")

        profile_response: APIResponse | None = None
        profile_fetch_error: str | None = None
        try:
            profile_response = UserDataAPIClient.fetch_user_profile(sub_id=sub)
            app.logger.debug(f"profile_response is {profile_response}")
        except requests.Timeout:
            profile_fetch_error = "timeout"
        except requests.RequestException:
            profile_fetch_error = "failure"

        # If we have an external subject but no local user yet, ask Profiles
        # for the full profile and create the KCWorks user.
        if (
            not user
            and isinstance(profile_response, APIResponse)
            and profile_response.data
        ):
            app.logger.debug(f"creating new user")
            user = CILogonHelpers.create_new_user(profile_response)
            app.logger.debug(f"created new user {user}")

        # Ensure the external identity is linked (idempotent via suppression).
        if user:
            with contextlib.suppress(AlreadyLinkedError):
                CILogonHelpers.link_user_to_oauth_identifier(user, "cilogon", sub)

            app.logger.debug(f"updating user from remote API")
            try:
                current_remote_user_data_service.update_user_from_remote(
                    system_identity,
                    user.id,
                    "knowledgeCommons",
                    sub,
                    remote_data=profile_response,
                )
            except Exception as exc:
                app.logger.warning(
                    "Login-time user-data update failed for sub=%s: %r; "
                    "login proceeds.",
                    sub,
                    exc,
                )
        else:
            if profile_fetch_error == "timeout":
                raise UserDataRequestTimeout
            raise UserDataRequestFailed

        return user, final_redirect
