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

from ..client import UserDataAPIClient
from ..errors import UserDataRequestFailed, UserDataRequestTimeout
from ..proxies import current_remote_user_data_service
from ..types.auth import AccountInfoDict
from .auth import CILogonHelpers


def extract_bearer_token(header_string: str) -> str:
    """Extract the actual bearer token from an Authorization header.

    Raises:
        ValueError: If the header string is None, malformed, or
          the token itself is empty.

    Returns:
        str: The bearer token.
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

    @staticmethod
    def decrypt_broker_token(token: str) -> dict:
        """Decrypt an AES-256-CBC broker token using the shared secret.

        Args:
            token: The base64url-encoded encrypted token string.

        Returns:
            The decrypted payload as a dict.

        Raises:
            ValueError: If the token cannot be decrypted or parsed.
        """
        secret = os.getenv("COMMONS_PROFILES_API_TOKEN")
        if not secret:
            raise ValueError("COMMONS_PROFILES_API_TOKEN environment variable not set")
        encoder = SecureParamEncoder(secret)
        return encoder.decode(token)

    @staticmethod
    def validate_nonce(nonce: str) -> bool:
        """Validate a broker nonce via the Profiles microservice.

        Args:
            nonce: The nonce string extracted from the broker token payload.

        Returns:
            True if the nonce is valid, False otherwise.
        """
        verify_url = app.config.get("SSO_BROKER_VERIFY_NONCE_URL")
        if not verify_url:
            app.logger.error("SSO_BROKER_VERIFY_NONCE_URL not configured")
            return False

        bearer_token = os.getenv("COMMONS_PROFILES_API_TOKEN")
        if not bearer_token:
            app.logger.error("COMMONS_PROFILES_API_TOKEN not set")
            return False

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
            return resp.json().get("valid", False) is True
        except Exception:
            app.logger.exception("Nonce validation request failed")
            return False

    @staticmethod
    def process_broker_payload(payload: dict) -> tuple[User | None, str | None]:
        """Extract user identity, find/create th KCWorks user, and update their data.

        Args:
            payload: The decrypted broker token dict. Expected keys include
                - kc_username (str)
                - primary_email (str)
                - nonce (str)
                - final_redirect (str)
                - userinfo (dict): With 'sub', 'email', etc.

        Raises:
            UserDataRequestFailed: If the user's data could not be retrieved from
              the remote endpoint's response.
            UserDataRequestTimeout: If the request to the remote endpoint times out.

        Returns:
            A tuple of (user, final_redirect). `user` is None if the payload
            did not contain enough information to identify or create a user.
        """
        userinfo = payload.get("userinfo") or {}
        sub = payload.get("sub") or userinfo.get("sub")
        final_redirect = payload.get("final_redirect", "/")

        if not sub:
            return None, final_redirect

        kc_username = payload.get("kc_username") or payload.get("username")
        email = payload.get("primary_email") or userinfo.get("email")
        orcid = userinfo.get("orcid") or payload.get("orcid")

        account_info: AccountInfoDict = {
            "external_id": sub,
            "external_method": "cilogon",
        }
        if email or kc_username:
            account_info["user"] = {
                "email": email or "",
                "profile": {
                    "identifier_orcid": orcid or "",
                    "identifier_kc_username": kc_username or "",
                },
            }

        user = CILogonHelpers.get_user_from_account_info(account_info)
        try:
            profile_response = UserDataAPIClient.fetch_user_profile(sub_id=sub)
        except requests.Timeout:
            profile_fetch_error = "timeout"
        except requests.RequestException:
            profile_fetch_error = "failure"

        # If we have an external subject but no local user yet, ask Profiles
        # for the full profile and create the KCWorks user.
        if not user and sub and profile_response and profile_response.data:
            user = CILogonHelpers.create_new_user(profile_response)

        # Ensure the external identity is linked (idempotent via suppression).
        if user:
            with contextlib.suppress(AlreadyLinkedError):
                CILogonHelpers.link_user_to_oauth_identifier(user, "cilogon", sub)

            # At login time we never want a transient Profiles-side
            # failure to block a user from logging in.
            try:
                current_remote_user_data_service.update_user_from_remote(
                    system_identity,
                    user.id,
                    "knowledgeCommons",
                    sub,
                    remote_date=profile_response,
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
            else:
                raise UserDataRequestFailed

        return user, final_redirect
