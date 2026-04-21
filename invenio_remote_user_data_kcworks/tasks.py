# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Celery task to update user data from remote API."""

import json
from typing import Any

from celery import shared_task
from flask import current_app as app
from invenio_access.permissions import system_identity
from invenio_accounts.models import UserIdentity
from .proxies import (
    current_remote_user_data_service,
    current_remote_group_service,
)
from .errors import NoIDPFoundError


@shared_task(ignore_result=True)
def do_user_data_update(
    user_id: int, idp: str | None = None, remote_id: str | None = None, **kwargs
) -> dict[str, Any]:
    """Perform a user metadata update.

    Args:
        user_id: The local ID of the user to update.
        idp: The remote service configuration to use for the update.
        remote_id: The ID of the user on the remote system.

    Returns:
        Plain dict summarizing the run (IDs, group names, group deltas, and
        optional user-field changes when the service returns a dict). Safe for
        Celery's JSON result backend; not the raw service tuple.
    """
    with app.app_context():
        if not idp:
            my_user_identity = UserIdentity.query.filter_by(
                id_user=user_id, method=idp or "cilogon"
            ).first()
            # will have a UserIdentity if the user has logged in via an IDP
            if my_user_identity is not None:
                idp = my_user_identity.method
                remote_id = my_user_identity.id

        if idp:
            service = current_remote_user_data_service

            user, updated_data, groups, groups_changes = (
                service.update_user_from_remote(
                    system_identity, user_id, idp, remote_id
                )
            )
            summary: dict[str, Any] = {
                "user_id": user_id,
                "idp": idp,
                "remote_id": remote_id,
                "completed_user_id": user.id if user is not None else None,
                "groups": list(groups),
                "group_changes": dict(groups_changes)
                if isinstance(groups_changes, dict)
                else {},
            }
            if isinstance(updated_data, dict):
                summary["user_field_changes"] = updated_data
            else:
                summary["user_field_changes"] = None
                summary["user_field_payload_type"] = (
                    type(updated_data).__name__ if updated_data is not None else None
                )
            encoded = json.dumps(summary, default=str)
            return json.loads(encoded)
        else:
            raise NoIDPFoundError(f"No IDP found for user {user_id}")


@shared_task(ignore_result=False)
def do_group_data_update(idp, remote_id, **kwargs):
    """Perform a group metadata update."""

    with app.app_context():
        service = current_remote_group_service
        service.update_group_from_remote(system_identity, idp, remote_id)
        return True
