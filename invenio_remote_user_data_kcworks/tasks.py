# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Celery tasks to update user and group data from remote API."""

import functools
import json
import time
import uuid
from collections.abc import Callable
from typing import Any, Literal

from celery import shared_task
from flask import current_app as app
from invenio_access.permissions import system_identity
from invenio_accounts.models import UserIdentity
from invenio_cache.proxies import current_cache as cache
from .proxies import (
    current_remote_user_data_service,
    current_remote_group_service,
)
from .errors import NoIDPFoundError

USER_DATA_UPDATE_LOCK_SUFFIX = "user-data-updating"
GROUP_DATA_UPDATE_LOCK_SUFFIX = "group-data-updating"


def update_lock_backoff_seconds(attempt: int) -> float:
    """Seconds to sleep before lock retry attempt ``attempt`` (0-based).

    Uses progressive backoff: ``initial_backoff + (attempt * backoff_step)``.
    """
    return app.config["REMOTE_USER_DATA_UPDATE_LOCK_INITIAL_BACKOFF"] + (
        attempt * app.config["REMOTE_USER_DATA_UPDATE_LOCK_BACKOFF_STEP"]
    )


class UpdateLockNotHeld(Exception): ...


class UserUpdateLock:
    """Per-entity mutex lock backed by Redis (``invenio_cache``)."""

    def __init__(self, key_suffix: str) -> None:
        self.token: str | None = None
        self.key: str | None = None
        self.status: Literal["waiting", "held"] | None = None
        self.key_suffix = key_suffix

    def _format_key(self, lock_id: str | int) -> str:
        return f"{str(lock_id)}:{self.key_suffix}"

    def _normalize_token(self, value: str | bytes) -> str:
        return value.decode() if isinstance(value, bytes) else value

    def acquire(self, lock_id: str | int) -> None:
        """Try to acquire the lock for ``lock_id``.

        Sets ``status`` to ``held`` on success or ``waiting`` if another holder
        owns the key.
        """
        self.key = self._format_key(lock_id)
        token = str(uuid.uuid4())
        lock_timeout = app.config["REMOTE_USER_DATA_UPDATE_LOCK_TIMEOUT"]
        if cache.add(self.key, token, timeout=lock_timeout):
            self.token = token
            self.status = "held"
        else:
            self.token = None
            self.status = "waiting"

    def release(self) -> None:
        """Release the lock if this holder still owns it."""
        if not self.key or not self.token:
            return
        current = cache.get(self.key)
        if current is None:
            return
        if self._normalize_token(current) == self.token:
            cache.delete(self.key)
        else:
            app.logger.error(
                f"Could not release update task lock {self.key}. Token did not match."
            )

    def __enter__(self) -> "UserUpdateLock":
        if self.status != "held":
            raise UpdateLockNotHeld(f"Cannot acquire lock with status {self.status!r}")
        else:
            return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.release()
        return False


def with_update_task_lock(lock_id_resolver: Callable, key_suffix: str):
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with app.app_context():
                attempt = 0
                lock = UserUpdateLock(key_suffix)
                lock_id = lock_id_resolver(*args, **kwargs)
                fallback_payload = {
                    "lock_id": str(lock_id),
                    "key_suffix": key_suffix,
                }

                if app.config["REMOTE_USER_DATA_UPDATE_LOCK_ENABLED"]:
                    for x in range(app.config["REMOTE_USER_DATA_UPDATE_LOCK_MAX_RETRIES"]):
                        current_backoff = update_lock_backoff_seconds(attempt)
                        lock.acquire(lock_id)
                        try:
                            with lock:
                                return func(*args, **kwargs)
                        except UpdateLockNotHeld:
                            time.sleep(current_backoff)
                            attempt += 1
                            continue

                    return {
                        **fallback_payload,
                        "status": "timeout",
                        "reason": "Max retries reached before lock could be acquired",
                    }
                else:
                    return func(*args, **kwargs)

        return wrapper

    return decorator


@shared_task(ignore_result=True)
@with_update_task_lock(
    lock_id_resolver=lambda user_id, *args, **kwargs: int(
        user_id
    ),  # we should always have user_id
    key_suffix=USER_DATA_UPDATE_LOCK_SUFFIX,
)
def do_user_data_update(
    user_id: int,
    idp: str | None = None,
    remote_id: str | None = None,
    kc_username: str | None = None,
    **kwargs,
) -> dict[str, Any]:
    """Perform a user metadata update.

    Args:
        user_id: The local ID of the user to update.
        idp: The remote service configuration to use for the update.
        remote_id: The OAuth ``sub`` on the remote system, when known.
        kc_username: KC member name for Profiles API lookup (webhook path).
        **kwargs: Reserved for future Celery options.

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
                    system_identity,
                    user_id,
                    idp,
                    remote_id=remote_id,
                    kc_username=kc_username,
                )
            )
            summary: dict[str, Any] = {
                "user_id": user_id,
                "idp": idp,
                "remote_id": remote_id,
                "kc_username": kc_username,
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
@with_update_task_lock(
    lock_id_resolver=lambda idp, remote_id, *args, **kwargs: f"{idp}:{remote_id}",
    key_suffix=GROUP_DATA_UPDATE_LOCK_SUFFIX,
)
def do_group_data_update(idp, remote_id, **kwargs):
    """Perform a group metadata update."""

    with app.app_context():
        service = current_remote_group_service
        service.update_group_from_remote(system_identity, idp, remote_id)
        return True
