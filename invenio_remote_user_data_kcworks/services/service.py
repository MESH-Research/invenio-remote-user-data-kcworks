#
# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Services for synchronizing remote group and user data into KCWorks."""

import os
from collections.abc import Mapping
from pprint import pformat
from typing import Any

import requests
from invenio_access.permissions import system_identity
from invenio_accounts.models import User
from invenio_accounts.proxies import current_accounts
from invenio_group_collections_kcworks.proxies import (
    current_group_collections_service,
)  # noqa
from invenio_group_collections_kcworks.service import remote_to_invenio_visibility
from invenio_records_resources.services import Service
from werkzeug.local import LocalProxy

from ..client import UserDataAPIClient
from ..errors import LocalUserNotFoundError, UserCreationFailed
from ..types.profiles_api import APIResponse, Profile
from ..utils.auth import CILogonHelpers
from .config import RemoteGroupDataServiceConfig, RemoteUserDataServiceConfig
from .group_roles import GroupRolesService


class RemoteGroupDataService(Service):
    """Service for updating a group's metadata from a remote server."""

    def __init__(self, app, config: RemoteGroupDataServiceConfig, **kwargs):
        """Constructor."""
        super().__init__(config=config)
        self.logger = app.logger
        self.updated_data = {}
        self.communities_service = LocalProxy(
            lambda: app.extensions["invenio-communities"].service
        )
        self.group_data_stale = True
        self.group_roles_service = GroupRolesService(self)

    def _update_community_metadata_dict(
        self, starting_dict: dict, new_data: dict
    ) -> dict:
        """Update a dictionary of community metadata with new data.

        Returns:
            The updated community payload.
        """
        assert new_data["id"] == starting_dict["custom_fields"]["kcr:commons_group_id"]

        metadata_updates = starting_dict["metadata"]
        custom_fields_updates = starting_dict["custom_fields"]

        if "avatar" in new_data.keys() and new_data["avatar"]:
            try:
                assert current_group_collections_service.update_avatar(
                    new_data["avatar"], starting_dict["id"]
                )
            except AssertionError:
                self.logger.error(f"Error uploading avatar for {new_data['id']} group.")

        if "url" in new_data.keys():
            metadata_updates["website"] = new_data["url"]

        if "visibility" in new_data.keys():
            custom_fields_updates["kcr:commons_group_visibility"] = new_data[
                "visibility"
            ]
            if "access" not in starting_dict:
                starting_dict["access"] = {}
            starting_dict["access"]["visibility"] = remote_to_invenio_visibility(
                new_data["visibility"]
            )
        if "description" in new_data.keys():
            custom_fields_updates["kcr:commons_group_description"] = new_data[
                "description"
            ]
        if "name" in new_data.keys():
            custom_fields_updates["kcr:commons_group_name"] = new_data["name"]

        starting_dict["metadata"].update(metadata_updates)
        starting_dict["custom_fields"].update(custom_fields_updates)

        return starting_dict

    def update_group_from_remote(
        self,
        identity,
        idp: str,
        remote_group_id: str,
        timeout: int | None = None,
        **kwargs,
    ) -> dict | None:
        """Update group data from remote server.

        If Invenio group roles for the remote group do not exist,
        they will not be created. If the group's collection exists,
        its metadata will be updated. If the group's collection
        does not exist, it will NOT be created. Creation of group
        collections is handled by the `invenio_group_collections_kcworks` service.

        If the update uncovers deleted group collections, the method will
        not update them. Instead, it will return a value of "deleted" for
        the "metadata_updated" key for that collection's slug in the
        return dictionary.

        This method is triggered by the
        :class:`invenio_remote_user_data_kcworks.views.RemoteUserDataUpdateWebhook`
        view.

        Parameters:
            idp (str): The identity provider name.
            remote_group_id (str): The identifier for the group on the
            remote service.
            timeout (int | None): Timeout in seconds for the remote groups
              endpoint request.
            **kwargs: Additional keyword arguments to pass to the method.

        Returns:
            dict: A dictionary of the updated group data. The keys are
            the slugs of the updated group collections. The values are
            dictionaries with the key "metadata_updated" and a value of
            "deleted" if the group collection was deleted, or the
            result of the update operation if the group collection was
            updated.

        Raises:
            RuntimeError: If more than one active group collection is
                found for the remote group.
        """
        self.require_permission(identity, "trigger_update")
        if not timeout:
            timeout = self.config.api_timeout
        results_dict = {}
        idp_config = self.config.endpoints_config[idp]
        remote_api_token = os.environ[idp_config["groups"]["token_env_variable_label"]]

        headers = {"Authorization": f"Bearer {remote_api_token}"}
        response = requests.get(
            f"{idp_config['groups']['remote_endpoint']}{remote_group_id}",
            headers=headers,
            timeout=timeout,
        )
        response.raise_for_status()
        raw_content = response.json()
        # Same shape as GroupCollectionsService: group at top level or under "results"
        group_metadata = raw_content.get("results", raw_content)

        # check if the group's collection(s) exists
        query_params = (
            f"+custom_fields.kcr\:commons_instance:{idp} "  # noqa:W605
            f"+custom_fields.kcr\:commons_group_id:"  # noqa:W605
            f"{remote_group_id}"
        )
        community_list = self.communities_service.search(
            system_identity, q=query_params, include_deleted=True
        )

        # use slugs from existing group collections if they exist
        # otherwise make new slug(s)
        if community_list.to_dict()["hits"]["total"] == 0:
            self.logger.debug(
                f"No group collection found for {idp} group {remote_group_id}"
            )
        else:
            deleted_comms = [
                community
                for community in community_list.to_dict()["hits"]["hits"]
                if community["deletion_status"]["is_deleted"] is True
            ]
            active_comms = [
                community
                for community in community_list.to_dict()["hits"]["hits"]
                if community["deletion_status"]["is_deleted"] is False
            ]

            if len(active_comms) > 1:
                raise RuntimeError(
                    f"Multiple active group collections found for {idp} "
                    f"group {remote_group_id}"
                )
            elif len(active_comms) == 1:
                community = active_comms[0]
                update_result = self.communities_service.update(
                    system_identity,
                    id_=community["id"],
                    data=self._update_community_metadata_dict(
                        community, group_metadata
                    ),
                )
                results_dict.setdefault(community["slug"], {})["metadata_updated"] = (
                    update_result.to_dict()
                )
            elif len(active_comms) == 0:
                self.logger.info(
                    f"No active group collection found for {idp} "
                    f"group {remote_group_id}"
                )

            if len(deleted_comms) > 0:
                for community in deleted_comms:
                    results_dict.setdefault(community["slug"], {})[
                        "metadata_updated"
                    ] = "deleted"

        return results_dict if results_dict else None

    def delete_group_from_remote(
        self, idp: str, remote_group_id: str, remote_group_name
    ) -> dict[str, list]:
        """Delete roles for a remote group if there is no corresponding group.

        If a group collection exists for the remote group, it will be
        disowned using the invenio_group_collections_kcworks module. Its metadata
        will be updated to remove the link to the remote collection.
        Its role-based memberships will be replaced by individual memberships
        for each currently-assigned user.

        Once any group collections have been disowned, any dangling Invenio
        roles will be deleted.

        # FIXME: What about the case of an orphaned group collection that is
        # soft-deleted? restored?

        Returns:
            A summary of disowned communities and deleted roles.
        """
        disowned_communities = []
        deleted_roles = []

        query_params = (
            f"+custom_fields.kcr\:commons_instance:{idp} "  # noqa:W605
            f"+custom_fields.kcr\:commons_group_id:"  # noqa:W605
            f"{remote_group_id}"
        )
        community_list = self.communities_service.search(
            system_identity, q=query_params
        )

        # make flat list of role names for all the slugs
        for community in community_list.to_dict()["hits"]["hits"]:
            # find all users with the group roles
            if not community["deletion_status"]["is_deleted"]:
                disowned_community = current_group_collections_service.disown(
                    system_identity,
                    community["id"],
                    community["slug"],
                    remote_group_id,
                    idp,
                )
                disowned_communities.append(disowned_community["slug"])

        stranded_roles = self.group_roles_service.get_roles_for_remote_group(
            remote_group_id=remote_group_id, idp=idp
        )
        for role in stranded_roles:
            # the query above returns a list of GroupItem objects that
            # can't be used to delete the roles straightforwardly
            if self.group_roles_service.delete_group(role.name):
                deleted_roles.append(role.name)
            else:
                self.logger.error(
                    f"RemoteGroupDataService: Error deleting role {role.id}"
                )

        return {
            "disowned_communities": disowned_communities,
            "deleted_roles": deleted_roles,
        }


class RemoteUserDataService(Service):
    """Service for updating a user's metadata from a remote server."""

    def __init__(self, app, config: RemoteUserDataServiceConfig, **kwargs):
        """Constructor."""
        super().__init__(config=config)
        self.logger = app.logger
        self.updated_data = {}
        self.communities_service = LocalProxy(
            lambda: app.extensions["invenio-communities"].service
        )

    @staticmethod
    def find_local_user_by_kc_username(kc_username: str) -> User | None:
        """Return a local user keyed by KC username, if one exists.

        Matches `identifier_kc_username`, legacy `UserIdentity` rows, and
        other heuristics shared with login matching.

        Args:
            kc_username: The Commons / KC member username.

        Returns:
            The matching `User`, or `None`.
        """
        if not kc_username:
            return None
        matched = CILogonHelpers.try_get_user_by_kc_username(
            kc_username, "knowledgeCommons"
        )
        if isinstance(matched, User):
            return matched
        if isinstance(matched, list):
            return matched[0] if len(matched) == 1 else None
        return None

    @staticmethod
    def fetch_subs_profile_for_kc_username(
        kc_username: str,
    ) -> APIResponse | None:
        """Fetch Profiles subs payload for a KC username when OAuth is linked.

        Uses `GET …/subs/{kc_username}/`, the canonical subs-index lookup for
        KC users who already have one or more linked identity providers.

        Args:
            kc_username: The Commons / KC member username.

        Returns:
            Parsed `APIResponse` when `data` is non-empty; otherwise `None`.
        """
        if not kc_username:
            return None
        response = UserDataAPIClient.fetch_user_profile(
            kc_username=kc_username,
            use_sub_endpoint=True,
        )
        if isinstance(response, APIResponse) and response.data:
            return response
        return None

    def _apply_profile_to_local_user(
        self,
        user: User,
        profile: Profile,
        *,
        remote_service: str,
        **kwargs,
    ) -> tuple[User, Mapping[str, Any], list[str], Mapping[str, Any]]:
        """Apply a Profiles `Profile` onto an existing local `User`.

        Shared by `update_user_from_remote` and members-only username ingest.

        Args:
            user: Local KCWorks user to update.
            profile: Remote Profiles profile payload.
            remote_service: Remote service key for group role naming
                (e.g. `"knowledgeCommons"`).
            **kwargs: Forwarded to `CILogonHelpers.update_local_user_data`.

        Returns:
            A four-tuple of `(user, user_field_changes, groups, group_changes)`.
        """
        self.logger.debug(f"final remote data profile: {pformat(profile)}")

        group_changes = CILogonHelpers.calculate_group_changes(profile, user)
        user_changes, new_data = CILogonHelpers.calculate_user_changes(profile, user)

        new_kc_username = (user_changes.get("user_profile") or {}).get(
            "identifier_kc_username"
        )
        old_kc_username = (
            (user.user_profile or {}).get("identifier_kc_username")
            if new_kc_username
            else None
        )

        updated_data = CILogonHelpers.update_local_user_data(
            user,
            new_data,
            user_changes,
            group_changes,
            remote_service,
            **kwargs,
        )

        if old_kc_username and new_kc_username and old_kc_username != new_kc_username:
            from ..tasks import rewrite_records_for_kc_username_change

            rewrite_records_for_kc_username_change.delay(
                user.id, old_kc_username, new_kc_username
            )

        return (
            user,
            updated_data["user"],
            updated_data["groups"],
            group_changes,
        )

    def provision_user_from_members_profile(
        self,
        identity,
        kc_username: str,
        *,
        idp: str = "knowledgeCommons",
        profile: Profile | None = None,
    ) -> User | None:
        """Create a local user from `members/{kc_username}/` without a `sub`.

        Used by username-list ingest for Commons members who exist on Profiles
        but have not linked OAuth yet. Does **not** create a `UserIdentity` or
        send Profiles status callbacks.

        Callers must skip when a local user with this KC username already exists
        (see `do_ingest_user_by_kc_username`).

        Args:
            identity: Invenio identity for permission checks.
            kc_username: Commons member username to provision.
            idp: Remote IDP configuration key (default `knowledgeCommons`).
            profile: Optional pre-fetched `Profile`; when omitted, fetched live
                from the members endpoint.

        Returns:
            The created local `User` after profile fields and groups are applied,
            or `None` when the remote profile is missing or user creation fails.
        """
        self.require_permission(identity, "trigger_update")

        remote_service = idp
        if idp in self.config.kc_remote_idps:
            remote_service = "knowledgeCommons"

        if profile is None:
            fetched = UserDataAPIClient.fetch_user_profile(
                kc_username=kc_username,
                use_sub_endpoint=False,
            )
            if not isinstance(fetched, Profile) or not fetched.username:
                self.logger.info(
                    "provision_user_from_members_profile: no members profile "
                    "for kc_username=%s",
                    kc_username,
                )
                return None
            profile = fetched

        try:
            user = CILogonHelpers.create_new_user(profile)
        except UserCreationFailed:
            self.logger.warning(
                "provision_user_from_members_profile: could not create user "
                "for kc_username=%s",
                kc_username,
            )
            return None

        self._apply_profile_to_local_user(
            user,
            profile,
            remote_service=remote_service,
        )
        return user

    def update_user_from_remote(
        self,
        identity,
        user_id: int,
        idp: str,
        remote_id: str,
        remote_data: APIResponse | None = None,
        **kwargs,
    ) -> tuple[
        User | None,
        Mapping[str, Any] | APIResponse | Profile | None,
        list[str],
        Mapping[str, Any],
    ]:
        """Main method to update user data from remote server.

        Parameters:
            user_id (int): The user's id in the Invenio database.
            idp (str): The identity provider name. This is not the oauth
                method name but rather the name of the user data source.
            remote_id (str): The identifier for the user on the remote idp
                service.
            remote_data (APIResponse | None): A pre-fetched user data API response
                to use instead of making a new remote request (optional)
            **kwargs: Additional keyword arguments to pass to the method.

        Returns:
            tuple: A four-tuple:

            0. User | None: The Invenio user after the update attempt, or
               None if the update failed with an exception.
            1. dict[str, Any] | APIResponse | Profile | None: On the
               successful local-update path, the sparse user diff from
               update_local_user_data (empty dict when no user fields changed);
               structurally matches UserChangesDict in types.py. On
               early-exit or error paths this may instead be the remote
               APIResponse or Profile payload, or None when nothing
               was returned.
            2. list[str]: Final group role names after membership updates,
               or an empty list when no group list was produced.
            3. dict: Group delta with keys 'added_groups',
               'dropped_groups', and 'unchanged_groups', or an empty dict on
               error/early-exit paths that do not compute group changes.

        Raises:
            LocalUserNotFoundError: If `user_id` does not resolve to a local user.

        """
        self.require_permission(identity, "trigger_update")

        # TODO: Can we refresh the user's identity if they're currently
        # logged in?
        self.logger.debug(
            f"Updating data from remote server -- user: {user_id}; "
            f"idp: {idp};"
            f" remote_id: {remote_id}."
        )
        if remote_data:
            self.logger.debug(f"Using pre-fetched remote data: {pformat(remote_data)}")

        remote_service = idp
        if idp in self.config.kc_remote_idps:
            remote_service = "knowledgeCommons"

        # Note: exceptions are intentionally allowed to propagate so callers
        # (the Celery tasks `do_user_created` and `do_user_data_update`)
        # can apply their HTTP-specific retry/reschedule policies and so
        # other unexpected errors are not silenced.
        # The login flow that calls this method synchronously (in
        # `utils.CILogonHelpers._existing_or_create_user_for_login`)
        # wraps it in its own defensive try/except so user logins are
        # never blocked by a Profiles-side failure.
        user = current_accounts.datastore.get_user_by_id(user_id)
        if user is None:
            raise LocalUserNotFoundError(f"No local Invenio user for id={user_id}")

        if remote_data is None or len(remote_data.data) == 0:
            remote_data: APIResponse | None = UserDataAPIClient.fetch_user_profile(
                sub_id=remote_id
            )

        if remote_data is None or len(remote_data.data) == 0:
            kc_username = user.user_profile.get("identifier_kc_username")
            remote_data: Profile | None = UserDataAPIClient.fetch_user_profile(
                kc_username=kc_username, use_sub_endpoint=False
            )
        else:
            if not remote_data.meta.authorized:
                self.logger.error(
                    "Problem with static bearer key for user data update."
                )
                return user, remote_data, [], {}

        if isinstance(remote_data, APIResponse) and len(remote_data.data) > 0:
            profile = remote_data.data[0].profile
        elif isinstance(remote_data, Profile):
            profile = remote_data
        else:
            # no record found on remote server
            self.logger.warning(f"User {remote_id} not found on remote server.")
            return user, remote_data, [], {}

        return self._apply_profile_to_local_user(
            user,
            profile,
            remote_service=remote_service,
            **kwargs,
        )

    def log_user_out_global(self, kc_username: str):
        """Send global logout signal to central IDMS service."""
        UserDataAPIClient.send_logout_to_profiles(kc_username)
