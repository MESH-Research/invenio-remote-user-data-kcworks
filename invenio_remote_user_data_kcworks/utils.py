# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Utility functions for invenio-remote-user-data-kcworks."""

import base64
import contextlib
import datetime
import hashlib
import json
import os
import time
from pprint import pformat
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

import invenio_oauthclient
import requests
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Response, request
from flask import current_app as app
from invenio_access.permissions import system_identity
from invenio_accounts import current_accounts
from invenio_accounts.errors import AlreadyLinkedError
from invenio_accounts.models import User, UserIdentity
from invenio_db import db
from uritools import uricompose, urisplit

from pydantic import ValidationError

from .client import UserDataAPIClient
from .errors import (
    BrokerNonceValidationError,
    BrokerPayloadExpiredError,
    BrokerExpiryValueError,
    BrokerPayloadProcessingError,
    BrokerTokenDecryptionError,
    UserCreationFailed,
    UserDataRequestFailed,
    UserDataRequestTimeout,
)
from .proxies import current_remote_user_data_service
from .services.group_roles import GroupRolesService
from .types import (
    AccountInfo,
    APIResponse,
    BrokerDecodedToken,
    CalculatedUserDataDict,
    GroupChangesDict,
    Profile,
    UpdateLocalUserDataResultDict,
    UserChangesDict,
)


def safe_redirect_target(target: str | None = None, arg_name: str | None = None) -> str:
    """Validate and normalize a redirect target to avoid open redirects.

    If no redirect target is specified, returns the validated request referrer
    if possible.

    Default fallback is to return the root path ('/').

    Arguments:
        target (str|None): A url string for the redirect target.
        arg_name (str|None): A string name for a request argument that carries the
          redirect url.

    Returns:
        str: The safe target for the redirect.
    """
    target = target if target else request.args.get(arg_name, "")
    allowed_hosts = app.config.get("APP_ALLOWED_HOSTS") or []

    if not allowed_hosts:
        app.logger.error("APP_ALLOWED_HOSTS not configred. Cannot validate redirects.")
        return "/"

    for redirect_target in (target, request.referrer):
        if not redirect_target:
            continue

        redirect_uri = urisplit(redirect_target)
        # Check if full url is allowed
        if redirect_uri.host and redirect_uri.host in allowed_hosts:
            return redirect_target
        # Handle relative paths safely
        elif redirect_uri.path:
            return uricompose(
                path=redirect_uri.getpath(),
                query=redirect_uri.getquery(),
                fragment=redirect_uri.getfragment(),
            )

    return "/"


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


class CILogonHelpers:
    """CILogon helper functions."""

    @staticmethod
    def _diff_between_nested_dicts(original, update):
        """Return the difference between two nested dictionaries.

        At present doesn't distinguish between additions and removals
        from lists
        """  # noqa
        diff = {}
        if not original:
            return update
        else:
            for key, value in update.items():
                if isinstance(value, dict):
                    diff[key] = CILogonHelpers._diff_between_nested_dicts(
                        original.get(key, {}), value
                    )
                elif isinstance(value, list):
                    diff[key] = [i for i in value if i not in original.get(key, [])] + [
                        x for x in original.get(key, []) if x not in value
                    ]
                else:
                    if original.get(key) != value:
                        diff[key] = value
            diff = {k: v for k, v in diff.items() if v}
            return diff

    @staticmethod
    def build_association_url(id_token) -> str:
        """Build the association URL.

        Returns:
            str: The url with encoded params as a string.
        """
        base_url = app.config.get("IDMS_BASE_ASSOCIATION_URL")
        params = {"userinfo": id_token}

        # encode the query string
        encoder = SecureParamEncoder(os.getenv("COMMONS_PROFILES_API_TOKEN"))

        encoded_params = {"userinfo": encoder.encode(params)}
        query_string = urlencode(encoded_params)
        parsed_url = urlparse(base_url)

        # Reconstruct the URL
        return urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            query_string,
            parsed_url.fragment,
        ))

    @staticmethod
    def get_user_from_account_info(account_info: AccountInfo) -> User | None:
        """Retrieve user object for the given request.

        Parameters:
            account_info (AccountInfo): External account payload
                ('external_id', 'external_method', 'email', 'orcid',
                'kc_username').

        Returns:
            An invenio_accounts.models.User instance or None.
        """
        if not account_info:
            return None

        # Try external ID first
        user = CILogonHelpers._try_get_user_by_external_id(account_info)
        if isinstance(user, User):
            app.logger.debug("User found by external ID (CILogon)")
            return user

        # Try ORCID lookup before kc username (more universal)
        user = CILogonHelpers._try_get_user_by_orcid(account_info.orcid)
        if isinstance(user, User):
            app.logger.debug("User found by ORCID")
            return user

        # Try KC username lookup before email (more reliable)
        user = CILogonHelpers.try_get_user_by_kc_username(
            account_info.kc_username,
            account_info.external_method,
        )
        # kc_username check can return a list of Users,
        # in which case we log an error and continue.
        if isinstance(user, User):
            app.logger.debug("User found by KC username")
            return user
        elif isinstance(user, list):
            app.logger.error(
                f"Multiple users found with KC username {account_info.kc_username}"
            )

        # Try email lookup
        app.logger.debug(pformat(account_info.model_dump()))
        user = CILogonHelpers._try_get_user_by_email(account_info.email)
        if isinstance(user, User):
            app.logger.debug("User found by email")
            app.logger.debug(user.id)
            app.logger.debug(user.email)
            return user

        app.logger.debug("No user found for account info.")

        return None

    @staticmethod
    def _try_get_user_by_external_id(account_info: AccountInfo) -> User | None:
        """Try to get user by external ID.

        Returns:
            User: A matching User when one exists.
            None: None when no matching user exists.
        """
        try:
            return_value = UserIdentity.get_user(
                account_info.external_method, account_info.external_id
            )
            return return_value
        except Exception:
            pass
        return None

    @staticmethod
    def _try_get_user_by_orcid(orcid: str | None) -> User | None:
        """Try to get user by ORCID.

        Returns:
            User: A matching User when one exists.
            None: None when no matching user exists.
        """
        if not orcid:
            return None

        try:
            return User.query.filter(
                User._user_profile.op("->>")("identifier_orcid") == orcid
            ).one_or_none()
        except Exception:
            pass
        return None

    @staticmethod
    def try_get_user_by_kc_username(
        kc_username: str | None, external_method: str | None
    ) -> User | list[User] | None:
        """Try to get user by KC username.

        Returns:
            User: if a matching user is found.
            list[User]: if multiple matching users are found.
            None: if no matching users are found.
        """
        app.logger.debug(
            f"in try_get_user_by_kc_username: looking for {kc_username} with "
            f"{external_method}"
        )
        if not kc_username:
            return None

        try:
            # try profile field
            user = User.query.filter(
                User._user_profile.op("->>")("identifier_kc_username") == kc_username
            ).all()
            app.logger.debug(f"user with kc id in profile field: {user}")

            # try legacy external identifier (used to use kc id as sub id)
            if external_method and not user:
                user = UserIdentity.get_user("knowledgeCommons", kc_username)
                app.logger.debug(f"user with kc id as legacy external id: {user}")

            # try with username as a direct valid kc identifier
            if not user:
                user = User.query.filter_by(username=f"{kc_username}").one_or_none()
                app.logger.debug(f"user with username as kc id: {user}")

            # try with kc prefix
            if external_method and not user:
                user = User.query.filter_by(
                    username=f"knowledgeCommons-{kc_username}"
                ).one_or_none()
                app.logger.debug(f"user with username as kc id with prefix: {user}")
            if external_method and not user:
                user = User.query.filter_by(
                    username=f"knowledgecommons-{kc_username}"
                ).one_or_none()
                app.logger.debug(f"user with username as kc id with prefix: {user}")
            if user:
                return user
        except Exception:
            pass
        return None

    @staticmethod
    def _try_get_user_by_email(email: str | None) -> User | None:
        """Try to get user by email.

        Returns:
            User: A matching User when one exists.
            None: None when no matching user exists.
        """
        if not email:
            return None

        try:
            return User.query.filter_by(email=email).one_or_none()
        except Exception:
            pass
        return None

    @staticmethod
    def link_user_to_oauth_identifier(
        user: User, external_method: str, external_id: str
    ) -> None:
        """Ensure that a user has a linked identity with the  external ID."""
        # TODO: deduplicate this function
        app.logger.debug(f"linking {user.id} with {external_method}, {external_id}")
        existing_identity = UserIdentity.query.filter_by(
            method=external_method, id=external_id, id_user=user.id
        ).first()
        app.logger.debug(f"existing_identity: {existing_identity}")

        if existing_identity:
            app.logger.debug("User already has identity linked to CILogon")
        else:
            app.logger.debug("Creating new identity for CILogon")
            _ = UserIdentity.create(
                user=user, method=external_method, external_id=external_id
            )
            db.session.commit()
            app.logger.debug("New identity created")

    @staticmethod
    def _update_invenio_group_memberships(
        user: User, changed_memberships: dict, **kwargs
    ) -> list[str]:
        """Update the user's group role memberships.

        If an added group role does not exist, it will be created. If a
        dropped group role does not exist, it will be ignored. If a
        dropped group role is left with no members, it will be deleted
        from the system roles.

        Returns:
            list: The updated list of group role names.
        """
        grouper = GroupRolesService(None)
        updated_local_groups = [r.name for r in user.roles]

        for group_name in changed_memberships["added_groups"]:
            group_role = grouper.find_or_create_group(group_name)
            if (
                group_role
                and grouper.add_user_to_group(group_role.name, user) is not None
            ):
                updated_local_groups.append(group_role.name)

        for group_name in changed_memberships["dropped_groups"]:
            group_role = grouper.find_group(group_name)

            if (
                group_role
                and grouper.remove_user_from_group(group_role, user) is not None
            ):
                updated_local_groups.remove(group_role.name)
                # NOTE: We don't delete the group role because that would
                # potentially disrupt roles being used for collections
        assert updated_local_groups == [r.name for r in user.roles]

        return updated_local_groups

    @staticmethod
    def update_local_user_data(
        user: User,
        new_data: CalculatedUserDataDict,
        user_changes: UserChangesDict,
        group_changes: dict,
        remote_service: str,
        **kwargs,
    ) -> UpdateLocalUserDataResultDict:
        """Update Invenio user data for the supplied identity.

        Parameters:
            user (User): The user to be updated.
            new_data (CalculatedUserDataDict): The new user data.
            user_changes (UserChangesDict): Sparse diff of changed user fields.
            group_changes (dict): Group membership delta with keys
                'added_groups', 'dropped_groups', and 'unchanged_groups'.
            remote_service (str): The name of the remote service providing
                the user data update.
            **kwargs: Additional options forwarded to group-role update helpers.

        Returns:
            UpdateLocalUserDataResultDict: Result of applying updates. Has two
              keys:

            - user (UserChangesDict): Sparse diff of fields written to the
                database when user_changes was non-empty; otherwise an empty dict.
                May include top-level keys 'active', 'username', 'email',
                'preferences', and nested 'user_profile' (see
                UserChangesDict in types.py).
            - groups (list[str]): Role names representing the user's group
                memberships after this update (either from
                _update_invenio_group_memberships or unchanged groups).
        """
        updated_data: UpdateLocalUserDataResultDict = {"user": {}, "groups": []}
        if user_changes:
            if user.username != new_data["username"]:
                # FIXME: Workaround for potential username collision
                # with a legacy account.
                if len(User.query.filter_by(username=new_data["username"]).all()) == 0:
                    user.username = new_data["username"]
                else:
                    app.logger.error(
                        f"Could not update username from remote for user {user.id}. "
                        "Collision with existing KCWorks account."
                    )

            user.user_profile = new_data["user_profile"]
            user.preferences = new_data["preferences"]

            if user.email != new_data["email"]:
                # FIXME: Workaround for potential email collision
                # Shouldn't be necessary now that Profiles is sending
                # a primary_email, but keeping this in case.
                # if email changes, keep the old email as an
                # `identifier_email` in the user_profile
                if len(User.query.filter_by(email=new_data["email"]).all()) == 0:
                    user.user_profile["identifier_email"] = user.email
                    user.email = new_data["email"]
                else:
                    app.logger.error(
                        f"Could not update email from remote for user {user.id}. "
                        "Collision with existing KCWorks account."
                    )
            current_accounts.datastore.commit()
            updated_data["user"] = user_changes
        if group_changes.get("added_groups") or group_changes.get("dropped_groups"):
            updated_data["groups"] = CILogonHelpers._update_invenio_group_memberships(
                user, group_changes, **kwargs
            )
        else:
            updated_data["groups"] = group_changes["unchanged_groups"] or []

        return updated_data

    @staticmethod
    def calculate_user_changes(
        profile: APIResponse | Profile, user: User
    ) -> tuple[UserChangesDict, CalculatedUserDataDict]:
        """Calculate user-field changes from remote profile data.

        Parameters:
            profile (APIResponse | Profile): Remote profile payload as either a full
                API response wrapper or a direct profile object.
            user (User): Local Invenio user to compare against.

        Returns:
            tuple[UserChangesDict, CalculatedUserDataDict]: A pair of dicts.

            0 (UserChangesDict): Sparse diff between the local
               user state and the desired remote-backed state. Only keys that
               differ are present.

            1 (CalculatedUserDataDict): Full normalized data for a user after
               a successful application of the changes: Has the keys 'active',
               'username', 'email', 'preferences' (including visibility
               flags), and 'user_profile' nested dict with 'full_name', 'name_parts'
               (JSON string), 'identifier_kc_username', optional 'affiliations' and
               'identifier_orcid', etc. (see CalculatedUserDataDict in types.py).
        """
        initial_user_data = {
            "username": user.username,
            "preferences": user.preferences,
            "roles": user.roles,
            "email": user.email,
            "active": user.active,
        }

        try:
            initial_user_data["user_profile"] = user.user_profile
            app.logger.debug(f"Initial user profile: {user.user_profile}")
        except ValueError:
            app.logger.error(
                f"Error fetching initial user profile data for user {user.id}. "
                f"Some data in db was invalid. Starting fresh with incoming "
                "data."
            )
            initial_user_data["user_profile"] = {}

        new_data: dict = {"active": True}
        new_data["user_profile"] = {**initial_user_data["user_profile"]}

        # reassign profile
        if isinstance(profile, APIResponse):
            profile = profile.data[0].profile

        new_data["user_profile"].update({
            "full_name": profile.name,
            "name_parts": json.dumps({
                "first": profile.first_name,
                "last": profile.last_name,
            }),
        })
        if profile.institutional_affiliation:
            new_data["user_profile"]["affiliations"] = profile.institutional_affiliation
        if profile.orcid and profile.orcid != "":
            new_data["user_profile"]["identifier_orcid"] = profile.orcid
        new_data["user_profile"]["identifier_kc_username"] = profile.username
        new_data["username"] = profile.username
        new_data["email"] = profile.email
        new_data["preferences"] = user.preferences
        new_data["preferences"].update({
            "visibility": "public",
            "email_visibility": "public",
        })
        user_changes = CILogonHelpers._diff_between_nested_dicts(
            initial_user_data, new_data
        )
        return user_changes, new_data

    @staticmethod
    def calculate_group_changes(
        profile: APIResponse | Profile, user
    ) -> GroupChangesDict:
        """Calculate the changes between the existing user and the data.

        Note that only roles related to Knowledge Commons groups are compared to
        calculate the changes. These are recognized by the prefix
        `knowledgeCommons---`.

        Returns:
            GroupChangesDict: Dictionary with three keys: `dropped_groups`,
              `added_groups`, and `unchanged_groups`. Each value is a list of
              group role names (strings).
        """
        local_groups = [r.name for r in user.roles]
        remote_groups = []

        group_changes: GroupChangesDict = {
            "dropped_groups": [],
            "added_groups": [],
            "unchanged_groups": local_groups,
        }

        if isinstance(profile, APIResponse):
            profile = profile.data[0].profile

        if profile and profile.groups:
            groups = [g for g in profile.groups]

            for g in groups:
                role_string = f"knowledgeCommons---{g.id}|{g.role}"
                remote_groups.append(role_string)

        # Also add roles for admin to remote superusers
        if profile and profile.is_superadmin is True:
            remote_groups.append("administration")
            remote_groups.append("administration-moderation")

        if remote_groups != local_groups:
            # Filter local groups to only knowledge commons groups for comparison
            local_kc_groups = [
                g for g in local_groups if g.split("---")[0] == "knowledgeCommons"
            ]

            group_changes = {
                "dropped_groups": [
                    g for g in local_kc_groups if g not in remote_groups
                ],
                "added_groups": [g for g in remote_groups if g not in local_kc_groups],
                "unchanged_groups": [
                    r
                    for r in local_groups
                    if r not in [g for g in local_kc_groups if g not in remote_groups]
                ],
            }

        return group_changes

    @staticmethod
    def create_new_user(result: APIResponse | Profile) -> User:
        """Create a new user.

        Returns:
            User: An invenio_accounts User object.
        """
        try:
            profile = (
                result.data[0].profile if isinstance(result, APIResponse) else result
            )

            app.logger.debug(f"Creating user: {profile.username}")
            user_info = {
                "username": profile.username,
                "email": profile.email,
                "active": True,
                "confirmed_at": (datetime.datetime.now(datetime.UTC)),
            }
            user = invenio_oauthclient.oauth.register_user(
                send_register_msg=True, **user_info
            )
            return user
        except (TypeError, IndexError, AttributeError):
            raise UserCreationFailed(
                "CILogonHelpers.create_new_user received unprocessable data."
            )


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
            raise UserDataRequestFailed

        return user, final_redirect


def update_nested_dict(original: dict, update: dict) -> dict[str, Any]:
    """Recursively updates values in a nested dict based on an update dict.

    Returns:
        dict[str, Any]: The same `original` input dict mutated in place.
          During recursion leaf values may be any type.
    """
    for key, value in update.items():
        if isinstance(value, dict):
            original[key] = update_nested_dict(original.get(key, {}), value)
        elif isinstance(value, list):
            original.setdefault(key, []).extend(value)
        else:
            original[key] = value
    return original


def diff_between_nested_dicts(original, update):
    """Return the difference between two nested dictionaries.

    At present doesn't distinguish between additions and removals
    from lists
    """  # noqa
    diff = {}
    if not original:
        return update
    else:
        for key, value in update.items():
            if isinstance(value, dict):
                diff[key] = diff_between_nested_dicts(original.get(key, {}), value)
            elif isinstance(value, list):
                diff[key] = [i for i in value if i not in original.get(key, [])] + [
                    x for x in original.get(key, []) if x not in value
                ]
            else:
                if original.get(key) != value:
                    diff[key] = value
        diff = {k: v for k, v in diff.items() if v}
        return diff
