#
# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Celery task to update user data from remote API."""

# from celery import current_app as current_celery_app
from celery import shared_task
from celery.utils.log import get_task_logger
from flask import current_app as app  # , session
from invenio_access.permissions import system_identity
from invenio_accounts.models import User, UserIdentity  # Role,

from .errors import NoIDPFoundError
from .proxies import (
    current_remote_group_service,
    current_remote_user_data_service,
)

task_logger = get_task_logger(__name__)


@shared_task(ignore_result=False)
def do_user_data_update(
    user_id: int, idp: str | None = None, remote_id: str | None = None, **kwargs
) -> tuple[User, dict, list[str], dict]:
    """Perform a user metadata update.

    Args:
        user_id: The local ID of the user to update.
        idp: The remote service configuration to use for the update.
        remote_id: The ID of the user on the remote system.
        kwargs: Additional keyword arguments

    Returns:
        A tuple containing
        - the updated User object
        - a dictionary of the updated user data (including only the changed
          keys and values).
        - A list of the updated user's group memberships.
        - A dictionary of the changes to the user's group memberships (with
          the keys "added_groups", "dropped_groups", and "unchanged_groups").
    """
    with app.app_context():
        if not idp:
            my_user_identity = UserIdentity.query.filter_by(
                id_user=user_id
            ).one_or_none()
            # will have a UserIdentity if the user has logged in via an IDP
            if my_user_identity is not None:
                idp = my_user_identity.method
                remote_id = my_user_identity.id

        if idp:
            service = current_remote_user_data_service

            # tuple: A tuple containing
            #     1. The updated user object from the Invenio database. If an
            #     error is encountered, this will be None.
            #     2. A dictionary of the updated user data (including only
            #     the changed keys and values).
            #     3. A list of the updated user's group memberships.
            #     4. A dictionary of the changes to the user's group
            #     memberships (with the keys "added_groups", "dropped_groups",
            #     and "unchanged_groups").
            user, updated_data, groups, groups_changes = (
                service.update_user_from_remote(
                    system_identity, user_id, idp, remote_id
                )
            )
            task_logger.info(f"updated_data: {updated_data}")
            return user.id, updated_data, groups, groups_changes
        else:
            raise NoIDPFoundError(f"No IDP found for user {user_id}")


@shared_task(ignore_result=False)
def do_group_data_update(idp, remote_id, **kwargs):
    """Perform a group metadata update."""
    with app.app_context():
        task_logger.info(dir(task_logger))
        task_logger.info(task_logger.handlers)
        app.logger.info(task_logger.handlers)
        service = current_remote_group_service
        service.update_group_from_remote(system_identity, idp, remote_id)
        return True
