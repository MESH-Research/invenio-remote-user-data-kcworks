# -*- coding: utf-8 -*-
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
from invenio_accounts.models import UserIdentity  # Role,
from .proxies import (
    current_remote_user_data_service,
    current_remote_group_service,
)

task_logger = get_task_logger(__name__)


@shared_task(ignore_result=False)
def do_user_data_update(user_id, idp=None, remote_id=None, **kwargs):
    """Perform a user metadata update."""

    with app.app_context():
        if not idp:
            my_user_identity = UserIdentity.query.filter_by(
                id_user=user_id
            ).one_or_none()
            # will have a UserIdentity if the user has logged in via an IDP
            if my_user_identity is not None:
                idp = my_user_identity.method
                remote_id = my_user_identity.id

        # task_logger.debug("doing task&&&&&&&")
        # print("doing task&&&&&&&")
        # task_logger.info(dir(task_logger))
        # task_logger.info(task_logger.handlers)
        # app.logger.info(task_logger.handlers)
        if idp:
            service = current_remote_user_data_service
            service.update_user_from_remote(
                system_identity, user_id, idp, remote_id
            )
        return True


@shared_task(ignore_result=False)
def do_group_data_update(idp, remote_id, **kwargs):
    """Perform a group metadata update."""

    with app.app_context():
        # task_logger.debug("doing task&&&&&&&")
        # print("doing task&&&&&&&")
        task_logger.info(dir(task_logger))
        task_logger.info(task_logger.handlers)
        app.logger.info(task_logger.handlers)
        service = current_remote_group_service
        service.update_group_from_remote(system_identity, idp, remote_id)
        return True
