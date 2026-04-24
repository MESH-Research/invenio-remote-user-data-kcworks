# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""User identity / CILogon authentication helpers."""

import datetime
import json
import os
from pprint import pformat
from urllib.parse import urlencode, urlparse, urlunparse

import invenio_oauthclient
from flask import current_app as app
from invenio_accounts import current_accounts
from invenio_accounts.models import User, UserIdentity
from invenio_db import db

from ..services.group_roles import GroupRolesService
from ..types import (
    AccountInfoDict,
    APIResponse,
    CalculatedUserDataDict,
    GroupChangesDict,
    Profile,
    UpdateLocalUserDataResultDict,
    UserChangesDict,
)


class UserIdentifierHelpers:
    """Helper functions in handling user identifiers."""

    @classmethod
    def username_from_user(cls, user: User | None) -> str | None:
        """Read the KC member name off a `User`.

        Prefers `user.user_profile["identifier_kc_username"]` (the
        canonical Profiles-side username) and falls back to
        `user.username` for legacy local accounts where the profile
        field was never populated. Returns `None` when both are empty.
        """
        if user is None:
            return None
        profile = user.user_profile or {}
        candidate = (profile.get("identifier_kc_username") or "").strip()
        if candidate:
            return candidate
        fallback = (user.username or "").strip()
        return fallback or None

    @classmethod
    def resolve_kc_username(
        cls,
        sub: str | None,
        user: User | None,
        *,
        method: str | None = None,
    ) -> str | None:
        """Resolve a KC member name for status callback purposes.

        The webhook payload's `id` is the OAuth `sub` (i.e. the value
        stored as `UserIdentity.id`), not the KC member name. To address
        the Profiles status callback we need the actual member name, so
        this helper performs the resolution chain:

        1. If a local `user` is already in hand, read from it directly
           (preferring `user_profile["identifier_kc_username"]`, with
           `user.username` as a legacy fallback).
        2. Otherwise look up `UserIdentity(method=..., id=sub)`,
           hydrate the corresponding `User`, and read the member name
           off it.

        Returns `None` when no member name can be resolved (e.g. an
        early failure in `do_user_created` before the local user has
        been created); callers should still send a status callback in
        that case but with `username=None`, addressed to the
        `unknown` member-name slot in the URL.

        Args:
            sub: The OAuth `sub` from the webhook (`UserIdentity.id`).
            user: The matched/created local user, or `None`.
            method: Optional `UserIdentity.method` to disambiguate the
                sub lookup when no `user` is supplied.

        Returns:
            A non-empty KC member name, or `None`.
        """
        if user is not None:
            return cls.username_from_user(user)
        if not sub:
            return None
        query = UserIdentity.query.filter_by(id=sub)
        if method:
            query = query.filter_by(method=method)
        user_identity = query.first()
        if user_identity is None:
            return None
        looked_up = User.query.get(user_identity.id_user)
        return cls.username_from_user(looked_up)


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
        # Lazy import to break the auth <-> broker circular dependency:
        # broker.py imports CILogonHelpers from this module at top level,
        # so we cannot import SecureParamEncoder from broker.py at top level here.
        from .broker import SecureParamEncoder

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
    def _get_external_id(account_info: AccountInfoDict) -> dict[str, str] | None:
        """Get external id from account info.

        Returns:
            dict[str, str]: A dictionary with 'id' and 'method' if the account
              info contains the external account association.
            None: If the account_info lacks the complete information.
        """
        if all(k in account_info for k in ("external_id", "external_method")):
            return dict(
                id=account_info["external_id"],
                method=account_info["external_method"],
            )
        return None

    @staticmethod
    def get_user_from_account_info(
        account_info: AccountInfoDict | None = None,
    ) -> User | None:
        """Retrieve user object for the given request.

        Extends the default account_get_user to allow for
        retrieving a user by ORCID as well as email.

        Uses either the access token or extracted account information to retrieve
        the user object.

        Expects the account info to be shaped like:
            {
                "user": {
                    "email": XXX,
                    "profile": {
                        "identifier_orcid": XXX,
                        "identifier_kc_username": XXX
                        }
                    },
                "external_method": "cilogon"
            }

        Parameters:
            account_info (AccountInfoDict | None): External account payload
                ('external_id', 'external_method', optional nested 'user').
                (Default: None)

        Returns:
            An invenio_accounts.models.User instance or None.
        """
        if not account_info:
            return None

        # Try external ID first
        user = CILogonHelpers._try_get_user_by_external_id(account_info)
        if user:
            app.logger.debug("User found by external ID (CILogon)")
            return user

        # Extract user profile safely
        user_profile = account_info.get("user", {}).get("profile", {})

        # Try ORCID lookup before kc username (more universal)
        user = CILogonHelpers._try_get_user_by_orcid(
            user_profile.get("identifier_orcid")
        )
        if user:
            app.logger.debug("User found by ORCID")
            return user

        # Try KC username lookup before email (more reliable)
        kc_username = user_profile.get("identifier_kc_username")
        user = CILogonHelpers.try_get_user_by_kc_username(
            kc_username,
            account_info.get("external_method"),
        )
        # kc_username check can return a list of Users,
        # in which case we log an error and continue.
        if user and isinstance(user, User):
            app.logger.debug("User found by KC username")
            return user
        elif isinstance(user, list):
            app.logger.error(f"Multiple users found with KC username {kc_username}")

        # Try email lookup
        email = account_info.get("user", {}).get("email")
        app.logger.debug(pformat(account_info))
        user = CILogonHelpers._try_get_user_by_email(email)
        if user:
            app.logger.debug("User found by email")
            app.logger.debug(user.id)
            app.logger.debug(user.email)
            return user

        app.logger.debug("No user found for account info.")

        return None

    @staticmethod
    def _try_get_user_by_external_id(account_info: AccountInfoDict) -> User | None:
        """Try to get user by external ID.

        Returns:
            User: A matching User when one exists.
            None: None when no matching user exists.
        """
        try:
            external_id = CILogonHelpers._get_external_id(account_info)
            if external_id:
                return_value = UserIdentity.get_user(
                    external_id["method"], external_id["id"]
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
    def build_account_info(api_result: APIResponse | None, sub: str) -> AccountInfoDict:
        """Build an account_info dict that looks as expected.

        Returns:
            AccountInfoDict: Structured dictionary of user info.
        """
        account_info: AccountInfoDict = {
            "external_id": sub,
            "external_method": "cilogon",
        }
        if api_result and api_result.data and len(api_result.data) > 0:
            profile_result = api_result.data[0].profile
            account_info["user"] = {
                "email": profile_result.email,
                "profile": {
                    "identifier_orcid": profile_result.orcid,
                    "identifier_kc_username": profile_result.username,
                },
            }
        return account_info

    @staticmethod
    def create_new_user(result) -> User:
        """Create a new user.

        Returns:
            User: An invenio_accounts User object.
        """
        app.logger.debug(f"Creating user: {result.data[0].profile.username}")
        user_info = {
            "username": result.data[0].profile.username,
            "email": result.data[0].profile.email,
            "active": True,
            "confirmed_at": (datetime.datetime.now(datetime.UTC)),
        }
        user = invenio_oauthclient.oauth.register_user(
            send_register_msg=True, **user_info
        )
        return user
