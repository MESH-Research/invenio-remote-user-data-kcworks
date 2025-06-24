# -*- coding: utf-8 -*-
#
# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

import datetime
from pprint import pformat

# frm pprint import pformat
from invenio_access.permissions import system_identity
from invenio_accounts.models import User, UserIdentity
from invenio_accounts.proxies import current_accounts
from invenio_db import db
from invenio_group_collections_kcworks.proxies import (
    current_group_collections_service,
)  # noqa
from invenio_queues.proxies import current_queues
from invenio_records_resources.services import Service
import json
import os

# from pprint import pprint
import requests
import traceback
from typing import Optional
from werkzeug.local import LocalProxy
from .components.groups import GroupRolesComponent
from .signals import remote_data_updated
from .tasks import do_group_data_update, do_user_data_update
from .utils import (
    diff_between_nested_dicts,
    CILogonHelpers,
)
from .api import fetch_user_profile, APIResponse, Profile


class RemoteGroupDataService(Service):
    """Service for updating a group's metadata from a remote server."""

    def __init__(self, app, config={}, **kwargs):
        """Constructor."""
        super().__init__(config=config, **kwargs)
        self.config = config
        self.config.permission_policy_cls = config.get(
            "REMOTE_USER_DATA_PERMISSION_POLICY"
        )
        self.endpoints_config = config.get("REMOTE_USER_DATA_API_ENDPOINTS")
        self.logger = app.logger
        self.updated_data = {}
        self.communities_service = LocalProxy(
            lambda: app.extensions["invenio-communities"].service
        )
        self.update_interval = datetime.timedelta(
            minutes=config["REMOTE_USER_DATA_UPDATE_INTERVAL"]
        )
        self.group_data_stale = True
        self.group_role_component = GroupRolesComponent(self)

        @remote_data_updated.connect_via(app)
        def on_webhook_update_signal(_, events: list) -> None:
            """Update group roles and metadata data from remote server
            when webhook is triggered.
            """

            self.logger.debug(
                "RemoteGroupDataService: webhook update signal received"
            )

            for event in current_queues.queues["user-data-updates"].consume():
                if event["entity_type"] == "groups" and event["event"] in [
                    "created",
                    "updated",
                ]:
                    celery_result = do_group_data_update.delay(  # noqa:F841
                        event["idp"], event["id"]
                    )  # type: ignore
                elif (
                    event["entity_type"] == "groups"
                    and event["event"] == "deleted"
                ):
                    raise NotImplementedError(
                        "Group role deletion from remote signal is not "
                        "yet implemented."
                    )

    def _update_community_metadata_dict(
        self, starting_dict: dict, new_data: dict
    ) -> dict:
        """Update a dictionary of community metadata with new data."""
        assert (
            new_data["id"]
            == starting_dict["custom_fields"]["kcr:commons_group_id"]
        )

        metadata_updates = starting_dict["metadata"]
        custom_fields_updates = starting_dict["custom_fields"]

        if "avatar" in new_data.keys() and new_data["avatar"]:
            try:
                assert current_group_collections_service.update_avatar(
                    starting_dict["id"], new_data["avatar"]
                )
            except AssertionError:
                self.logger.error(
                    f"Error uploading avatar for {new_data['id']} group."
                )

        if "url" in new_data.keys():
            metadata_updates["website"] = new_data["url"]

        if "visibility" in new_data.keys():
            custom_fields_updates["kcr:commons_group_visibility"] = new_data[
                "visibility"
            ]
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
        self, identity, idp: str, remote_group_id: str, **kwargs
    ) -> Optional[dict]:
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
            **kwargs: Additional keyword arguments to pass to the method.

        Returns:
            dict: A dictionary of the updated group data. The keys are
            the slugs of the updated group collections. The values are
            dictionaries with the key "metadata_updated" and a value of
            "deleted" if the group collection was deleted, or the
            result of the update operation if the group collection was
            updated.
        """
        self.require_permission(identity, "trigger_update")
        results_dict = {}
        idp_config = self.endpoints_config[idp]
        remote_api_token = os.environ[
            idp_config["groups"]["token_env_variable_label"]
        ]

        headers = {"Authorization": f"Bearer {remote_api_token}"}
        response = requests.get(
            f"{idp_config['groups']['remote_endpoint']}{remote_group_id}",
            headers=headers,
            timeout=30,
        )
        group_metadata = response.json()

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
            self.logger.error(
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
                results_dict.setdefault(community["slug"], {})[
                    "metadata_updated"
                ] = update_result.to_dict()
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

        stranded_roles = self.group_role_component.get_roles_for_remote_group(
            remote_group_id=remote_group_id, idp=idp
        )
        for role in stranded_roles:
            # the query above returns a list of GroupItem objects that
            # can't be used to delete the roles straightforwardly
            if self.group_role_component.delete_group(role.id):
                deleted_roles.append(role.id)
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

    def __init__(self, app, config={}, **kwargs):
        """Constructor."""
        super().__init__(config=config, **kwargs)
        self.config = config
        self.endpoints_config = config["REMOTE_USER_DATA_API_ENDPOINTS"]
        self.config.permission_policy_cls = config.get(
            "REMOTE_USER_DATA_PERMISSION_POLICY"
        )
        self.logger = app.logger
        self.updated_data = {}
        self.communities_service = LocalProxy(
            lambda: app.extensions["invenio-communities"].service
        )
        # TODO: Is there a risk of colliding operations?
        self.update_in_progress = False

        @remote_data_updated.connect_via(app)
        def on_webhook_update_signal(_, events: list) -> None:
            """Update user data from remote server when webhook is triggered.

            ...
            """
            self.logger.info("%%%%% webhook signal received")

            for event in current_queues.queues["user-data-updates"].consume():
                if (
                    event["entity_type"] == "users"
                    and event["event"] == "updated"
                ):
                    try:
                        # confirm that user exists in Invenio
                        my_user_identity = UserIdentity.query.filter_by(
                            id=event["id"]
                        ).one_or_none()
                        assert my_user_identity is not None

                        do_user_data_update.delay(  # noqa
                            my_user_identity.id_user, event["idp"], event["id"]
                        )  # noqa
                    except AssertionError:
                        self.logger.error(
                            f'Cannot update: user {event["id"]} does not exist'
                            " in Invenio."
                        )
                elif (
                    event["entity_type"] == "groups"
                    and event["event"] == "updated"
                ):
                    # TODO: implement group updates and group/user creation
                    pass

    def update_user_from_remote(
        self, identity, user_id: int, idp: str, remote_id: str, **kwargs
    ) -> tuple[Optional[User], APIResponse | Profile | None, list[str], dict]:
        """Main method to update user data from remote server.

        Parameters:
            user_id (int): The user's id in the Invenio database.
            idp (str): The identity provider name.
            remote_id (str): The identifier for the user on the remote idp
                service.
            **kwargs: Additional keyword arguments to pass to the method.

        Returns:
            tuple: A tuple containing
                1. The updated user object from the Invenio database. If an
                error is encountered, this will be None.
                2. A dictionary of the updated user data (including only
                the changed keys and values).
                3. A list of the updated user's group memberships.
                4. A dictionary of the changes to the user's group
                memberships (with the keys "added_groups", "dropped_groups",
                and "unchanged_groups").

        """
        self.require_permission(identity, "trigger_update")

        # TODO: Can we refresh the user's identity if they're currently
        # logged in?
        self.logger.warning(
            f"Updating data from remote server -- user: {user_id}; "
            f"idp: {idp};"
            f" remote_id: {remote_id}."
        )
        updated_data = {}

        try:
            user: User = current_accounts.datastore.get_user_by_id(user_id)
            remote_data: APIResponse = fetch_user_profile(sub_id=remote_id)

            for external_id in user.external_identifiers:
                self.logger.debug(f"External ID: {external_id}")
                if external_id.method == "knowledgeCommons":
                    self.logger.debug(f"Found KC ID: {external_id['id']}")
                    break

            # TODO: if we don't have a remote id using this, we need to use
            # the KC username to fetch the user, which is not a problem
            if not remote_data.data or len(remote_data.data) == 0:
                for external_id in user.external_ids:
                    if external_id["method"] == "knowledgeCommons":
                        remote_id = external_id["id"]
                        remote_data: Profile = fetch_user_profile(remote_id)
                        break
                pass
            else:
                if not remote_data.meta.authorized:
                    self.logger.error("Problem with static bearer key")
                    return user, remote_data, [], {}

            if (
                hasattr(remote_data, "data")
                and remote_data.data
                and len(remote_data.data) > 0
            ) or (
                hasattr(remote_data, "results")
                and remote_data.results
                and len(remote_data.results) > 0
            ):
                try:
                    profile = remote_data.data[0].profile
                except AttributeError:
                    profile = remote_data.results[0].profile

                # update the user profile
                user.username = profile.username
                user.full_name = profile.name
                user.email = profile.email

                group_changes = CILogonHelpers.calculate_group_changes(
                    profile, user
                )
                user_changes, new_data = CILogonHelpers.calculate_user_changes(
                    profile, user
                )

                updated_data = CILogonHelpers.update_local_user_data(
                    user,
                    new_data,
                    user_changes,
                    group_changes,
                    **kwargs,
                )

                self.logger.debug(f"User changes: {user_changes}")
                self.logger.debug(f"Group changes: {group_changes}")
                db.session.commit()

                return (
                    user,
                    updated_data["user"],
                    updated_data["groups"],
                    group_changes,
                )

            else:
                # no record found on remote server
                self.logger.error(
                    f"User {remote_id} not found on remote server."
                )
                return user, remote_data, [], {}

        except Exception as e:
            self.logger.error(
                f"Error updating user data from remote server: {repr(e)}"
            )
            self.logger.error(traceback.format_exc())
            return None, None, [], {}
