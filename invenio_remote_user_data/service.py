# -*- coding: utf-8 -*-
#
# This file is part of the invenio-remote-user-data package.
# Copyright (C) 2023, MESH Research.
#
# invenio-remote-user-data is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

import datetime
from pprint import pformat

# frm pprint import pformat
from invenio_access.permissions import system_identity
from invenio_accounts.models import User, UserIdentity, Role
from invenio_accounts.proxies import current_accounts
from invenio_communities.communities.services.results import CommunityItem

# from invenio_accounts.utils import jwt_create_token
from invenio_group_collections.utils import make_base_group_slug  # noqa
from invenio_group_collections.proxies import (
    current_group_collections_service,
)  # noqa
from invenio_queues.proxies import current_queues
from invenio_records_resources.services import Service

from invenio_users_resources.proxies import current_groups_service
from .tasks import do_group_data_update, do_user_data_update
import os

# from pprint import pprint
import requests
import traceback
from typing import Optional

# from typing import Optional
from werkzeug.local import LocalProxy
from .components.groups import GroupRolesComponent
from .signals import remote_data_updated
from .utils import (
    logger as update_logger,
    diff_between_nested_dicts,
)


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
        self.logger = update_logger
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
        self.logger.debug("Starting dict: " + pformat(starting_dict))
        self.logger.debug("New data: " + pformat(new_data))

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
        they will not be created. If the group's collection exists, its metadata
        will be updated. If the group's collection does not exist, it will NOT
        be created. Creation of group collections is handled by the
        `invenio_group_collections` service.

        If the update uncovers deleted group collections, the method will
        not update them. Instead, it will return a value of "deleted" for the "metadata_updated" key for that collection's slug in the return dictionary.

        This method is triggered by the
        :class:`invenio_remote_user_data.views.RemoteUserDataUpdateWebhook`
        view.

        Parameters:
            idp (str): The identity provider name.
            remote_group_id (str): The identifier for the group on the
            remote service.
            **kwargs: Additional keyword arguments to pass to the method.

        Returns:
            dict: A dictionary of the updated group data. The keys are the slugs of the updated group collections. The values are dictionaries with the key "metadata_updated" and a value of "deleted" if the group collection was deleted, or the result of the update operation if the group collection was updated.
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
        disowned using the invenio_group_collections module. Its metadata
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
        self.logger = update_logger
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
                        update_logger.error(
                            f'Cannot update: user {event["id"]} does not exist'
                            " in Invenio."
                        )
                elif (
                    event["entity_type"] == "groups"
                    and event["event"] == "updated"
                ):
                    # TODO: implement group updates and group/user creation
                    pass

    # TODO: decide whether to reimplement now that we're using webhooks
    # def _data_is_stale(self, user_id) -> bool:
    #     """Check whether user data is stale."""
    #     user_data_stale = True
    #     if (
    #         user_id
    #         and "user-data-updated" in session.keys()
    #         and type(session["user-data-updated"]) is not str
    #         and user_id in session["user-data-updated"].keys()
    #     ):
    #         if session["user-data-updated"][user_id]:
    #             last_update_dt = datetime.datetime.fromisoformat(
    #                 session["user-data-updated"][user_id]
    #             )
    #             interval = datetime.datetime.utcnow() - last_update_dt
    #             if interval <= self.update_interval:
    #                 user_data_stale = False
    #     return user_data_stale

    def update_user_from_remote(
        self, identity, user_id: int, idp: str, remote_id: str, **kwargs
    ) -> tuple[User, dict, list[str], dict]:
        """Main method to update user data from remote server.

        This method is triggered by the

        Parameters:
            user_id (int): The user's id in the Invenio database.
            idp (str): The identity provider name.
            remote_id (str): The identifier for the user on the remote idp
                service.
            **kwargs: Additional keyword arguments to pass to the method.

        Returns:
            tuple: A tuple containing
                1. The updated user object from the Invenio database.
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
        update_logger.info(
            f"Updating data from remote server -- user: {user_id}; "
            f"idp: {idp};"
            f" remote_id: {remote_id}."
        )
        updated_data = {}
        try:
            user = current_accounts.datastore.get_user_by_id(user_id)
            remote_data = self.fetch_from_remote_api(
                user, idp, remote_id, **kwargs
            )
            new_data, user_changes, groups_changes = [{}, {}, {}]
            if remote_data:
                new_data, user_changes, groups_changes = (
                    self.compare_remote_with_local(
                        user, remote_data, idp, **kwargs
                    )
                )
            if new_data:
                updated_data = self.update_local_user_data(
                    user, new_data, user_changes, groups_changes, **kwargs
                )
                assert sorted(updated_data["groups"]) == sorted(
                    [
                        *groups_changes["added_groups"],
                        *groups_changes["unchanged_groups"],
                    ]
                )
            update_logger.info(
                "User data successfully updated from remote "
                f"server: {updated_data}"
            )
            return (
                user,
                updated_data["user"],
                updated_data["groups"],
                groups_changes,
            )
        except Exception as e:
            update_logger.error(
                f"Error updating user data from remote server: {repr(e)}"
            )
            update_logger.error(traceback.format_exc())
            return None, None, None, None

    def fetch_from_remote_api(
        self, user: User, idp: str, remote_id: str, tokens=None, **kwargs
    ) -> dict:
        """Fetch user data for the supplied user from the remote API.

        Parameters:
            user (User): The user to be updated.
            idp (str): The SAML identity provider name.
            remote_id (str): The identifier for the user on the remote idp
                service.
            tokens (dict): A dictionary of API tokens for the remote
                API. Optional.

        Returns:
            dict: A dictionary of the user data returned by the remote api
                  endpoint.
        """
        remote_data = {}
        if "users" in self.endpoints_config[idp].keys():
            users_config = self.endpoints_config[idp]["users"]

            remote_api_token = None
            if (
                tokens and "users" in tokens.keys()
            ):  # allows injection for testing
                remote_api_token = tokens["users"]
            else:
                remote_api_token = os.environ[
                    users_config["token_env_variable_label"]
                ]
            if users_config["remote_identifier"] != "id":
                remote_id = getattr(user, users_config["remote_identifier"])
            api_url = f'{users_config["remote_endpoint"]}{remote_id}'

            callfuncs = {"GET": requests.get, "POST": requests.post}
            callfunc = callfuncs[users_config["remote_method"]]

            headers = {}
            if remote_api_token:
                headers = {"Authorization": f"Bearer {remote_api_token}"}
            update_logger.debug(f"API URL: {api_url}")
            response = callfunc(
                api_url, headers=headers, verify=False, timeout=10
            )
            if response.status_code != 200:
                update_logger.error(
                    f"Error fetching user data from remote API: {api_url}"
                )
                update_logger.error(
                    "Response status code: " + str(response.status_code)
                )
            try:
                # remote_data['groups'] = {'status_code': response.status_code,
                #                          'headers': response.headers,
                #                          'json': response.json(),
                #                          'text': response.text}
                remote_data["users"] = response.json()
            except requests.exceptions.JSONDecodeError:
                self.logger.error(
                    "JSONDecodeError: User group data API response was not"
                    " JSON:"
                )
                # self.logger.debug(f'{response.text}')

        return remote_data

    def compare_remote_with_local(
        self, user: User, remote_data: dict, idp: str, **kwargs
    ) -> tuple[dict, dict, dict]:
        """Compare remote data with local data and return changed data.

        No changes are made to the user object or db data in this method.
        The first return value includes the data that should be present in
        the updated user object. The second return value includes the
        change to make to the user object. The third return value includes
        the changes to make to the user's group memberships.

        Parameters:
            user (User): The user to be updated.
            remote_data (dict): The data fetched from the remote API.
            idp (str): The identity provider name.

        Returns:
            tuple: A tuple of dictionaries containing the new user data,
                   the changes to the user data, and the changes to the user's
                   group memberships.
        """
        initial_user_data = {
            "user_profile": user.user_profile,
            "username": user.username,
            "preferences": user.preferences,
            "roles": user.roles,
            "email": user.email,
            "active": user.active,
        }
        new_data = {"active": True}

        local_groups = [r.name for r in user.roles]
        group_changes = {
            "dropped_groups": [],
            "added_groups": [],
            "unchanged_groups": local_groups,
        }

        users = remote_data.get("users")
        if users:
            groups = users.get("groups")
            if groups:
                remote_groups = []
                for g in groups:
                    # Fetch group metadata from remote service
                    slug = make_base_group_slug(g["name"])
                    role_string = f"{idp}---{g['id']}|{g['role']}"
                    remote_groups.append(role_string)
                if remote_groups != local_groups:
                    group_changes = {
                        "dropped_groups": [
                            g
                            for g in local_groups
                            if g.split("---")[0] == idp
                            and g not in remote_groups
                        ],
                        "added_groups": [
                            g for g in remote_groups if g not in local_groups
                        ],
                    }

                    group_changes["unchanged_groups"] = [
                        r
                        for r in local_groups
                        if r not in group_changes["dropped_groups"]
                    ]
            new_data["user_profile"] = user.user_profile
            new_data["user_profile"].update(
                {
                    "full_name": users["name"],
                    "name_parts": {
                        "first": users["first_name"],
                        "last": users["last_name"],
                    },
                }
            )
            if users.get("institutional_affiliation"):
                new_data["user_profile"]["affiliations"] = users[
                    "institutional_affiliation"
                ]
            if users.get("orcid"):
                new_data["user_profile"].setdefault("identifiers", []).append(
                    {"identifier": users["orcid"], "scheme": "orcid"}
                )
            new_data["username"] = f'{idp}-{users["username"]}'
            new_data["email"] = users["email"]
            new_data["preferences"] = user.preferences
            new_data["preferences"].update(
                {
                    "visibility": "restricted",
                    "email_visibility": "restricted",
                }
            )
            if users.get("preferred_language"):
                new_data["preferences"]["locale"] = users["preferred_language"]
        user_changes = diff_between_nested_dicts(initial_user_data, new_data)
        return new_data, user_changes, group_changes

    def update_local_user_data(
        self,
        user: User,
        new_data: dict,
        user_changes: dict,
        group_changes: dict,
        **kwargs,
    ) -> dict:
        """Update Invenio user data for the supplied identity.

        Parameters:
            user (User): The user to be updated.
            new_data (dict): The new user data.
            user_changes (dict): The changes to the user data.
            group_changes (dict): The changes to the user's group memberships.

        Returns:
            dict: A dictionary of the updated user data with the keys "user"
                  and "groups".
        """
        updated_data = {}
        if user_changes:
            user.username = new_data["username"]
            user.user_profile = new_data["user_profile"]
            user.preferences = new_data["preferences"]
            user.email = new_data["email"]
            current_accounts.datastore.commit()
            # updated_data["user"] = current_users_service.update(
            #     system_identity, user.id, new_data
            # ).data
            updated_data["user"] = user_changes
        else:
            updated_data["user"] = []
        if group_changes.get("added_groups") or group_changes.get(
            "dropped_groups"
        ):
            updated_data["groups"] = self.update_invenio_group_memberships(
                user, group_changes, **kwargs
            )
        else:
            updated_data["groups"] = group_changes["unchanged_groups"] or []
        return updated_data

    def update_invenio_group_memberships(
        self, user: User, changed_memberships: dict, **kwargs
    ) -> list[str]:
        """Update the user's group role memberships.

        If an added group role does not exist, it will be created. If a
        dropped group role does not exist, it will be ignored. If a
        dropped group role is left with no members, it will be deleted
        from the system roles.

        Returns:
            list: The updated list of group role names.
        """
        grouper = GroupRolesComponent(self)
        updated_local_groups = [r.name for r in user.roles]
        self.logger.debug(
            "Got changed groups: " + pformat(changed_memberships)
        )
        for group_name in changed_memberships["added_groups"]:
            group_role = grouper.find_or_create_group(group_name)
            if (
                group_role
                and grouper.add_user_to_group(group_role, user) is not None
            ):
                updated_local_groups.append(group_role.name)
        for group_name in changed_memberships["dropped_groups"]:
            group_role = grouper.find_group(group_name)
            if (
                group_role
                and grouper.remove_user_from_group(group_role, user)
                is not None
            ):
                updated_local_groups.remove(group_role.name)
                # NOTE: We don't delete the group role because that would
                # potentially disrupt roles being used for collections
                #
                # remaining_members = grouper.get_current_members_of_group(
                #     group_role.name
                # )
                # if not remaining_members:
                #     grouper.delete_group(group_role.name)
        assert updated_local_groups == user.roles

        return updated_local_groups
