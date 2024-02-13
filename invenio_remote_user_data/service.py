# -*- coding: utf-8 -*-
#
# This file is part of the invenio-remote-user-data package.
# Copyright (C) 2023, MESH Research.
#
# invenio-remote-user-data is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

import datetime

# frm pprint import pformat
from invenio_accounts.models import User, UserIdentity  # Role,
from invenio_accounts.proxies import current_accounts

# from invenio_accounts.utils import jwt_create_token
from invenio_queues.proxies import current_queues
from invenio_records_resources.services import Service

# from invenio_users_resources.proxies import current_users_service
from flask import session  # after_this_request, request,
from .tasks import do_user_data_update
import os

# from pprint import pprint
import requests

# from typing import Optional
from werkzeug.local import LocalProxy
from .components.groups import GroupsComponent
from .signals import remote_data_updated
from .utils import logger as update_logger, diff_between_nested_dicts

# from .views import IDPUpdateWebhook


class RemoteUserDataService(Service):
    """Service for retrieving user data from a Remote server."""

    def __init__(self, app, config={}, **kwargs):
        """Constructor."""
        super().__init__(config=config, **kwargs)
        self.config = config["REMOTE_USER_DATA_API_ENDPOINTS"]
        self.logger = update_logger
        self.updated_data = {}
        self.communities_service = LocalProxy(
            lambda: app.extensions["invenio-communities"].service
        )
        self.update_interval = datetime.timedelta(
            minutes=app.config["REMOTE_USER_DATA_UPDATE_INTERVAL"]
        )
        self.user_data_stale = True
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

                        timestamp = datetime.datetime.utcnow().isoformat()
                        session.setdefault("user-data-updated", {})[
                            my_user_identity.id_user
                        ] = timestamp
                        celery_result = do_user_data_update.delay(  # noqa
                            my_user_identity.id_user, event["idp"], event["id"]
                        )
                        # self.logger.info('celery_result_id: '
                        #                  f'{celery_result.id}')
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

    def update_data_from_remote(
        self, user_id: int, idp: str, remote_id: str, **kwargs
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
        # TODO: Can we refresh the user's identity if they're currently
        # logged in?
        update_logger.debug(
            f"Updating data from remote server -- user: {user_id}; "
            f"idp: {idp};"
            f" remote_id: {remote_id}."
        )
        updated_data = {}
        user = current_accounts.datastore.get_user_by_id(user_id)
        remote_data = self.fetch_from_remote_api(
            user, idp, remote_id, **kwargs
        )
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
            assert sorted(updated_data["groups"]) == sorted([
                *groups_changes["added_groups"],
                *groups_changes["unchanged_groups"],
            ])
        return (
            user,
            updated_data["user"],
            updated_data["groups"],
            groups_changes,
        )

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
        if "users" in self.config[idp].keys():
            users_config = self.config[idp]["users"]

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
            update_logger.info(f"API URL: {api_url}")
            response = callfunc(api_url, headers=headers, verify=False)
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
        group_changes = {}
        users = remote_data.get("users")
        if users:
            groups = users.get("groups")
            if groups:
                remote_groups = [
                    f'{idp}|{g["name"]}|{g["role"]}' for g in groups
                ]
                local_groups = [r.name for r in user.roles]
                if remote_groups != local_groups:
                    group_changes = {
                        "dropped_groups": [
                            g
                            for g in local_groups
                            if g.split("|")[0] == idp
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
                else:
                    group_changes = {
                        "dropped_groups": [],
                        "added_groups": [],
                        "unchanged_groups": local_groups,
                    }
            new_data["user_profile"] = user.user_profile
            new_data["user_profile"].update({
                "full_name": users["name"],
                "name_parts": {
                    "first": users["first_name"],
                    "last": users["last_name"],
                },
            })
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
            new_data["preferences"].update({
                "visibility": "restricted",
                "email_visibility": "restricted",
            })
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
        if group_changes["added_groups"] or group_changes["dropped_groups"]:
            updated_data["groups"] = self.update_invenio_group_memberships(
                user, group_changes, **kwargs
            )
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
        grouper = GroupsComponent(self)
        updated_local_groups = [r.name for r in user.roles]
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
                remaining_members = grouper.get_current_members_of_group(
                    group_role.name
                )
                if not remaining_members:
                    grouper.delete_group(group_role.name)
        assert updated_local_groups == user.roles

        return updated_local_groups
