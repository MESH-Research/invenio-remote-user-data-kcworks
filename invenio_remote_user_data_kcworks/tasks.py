# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Celery tasks to update user and group data from remote API."""

import contextlib
import functools
import json
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from itertools import islice
from typing import Any, Literal

import requests
from celery import shared_task
from celery.exceptions import MaxRetriesExceededError
from flask import current_app as app
from invenio_access.permissions import system_identity
from invenio_accounts.errors import AlreadyLinkedError
from invenio_accounts.models import User, UserIdentity
from invenio_accounts.proxies import current_datastore as datastore
from invenio_cache.proxies import current_cache as cache
from invenio_db import db
from sqlalchemy.exc import IntegrityError

from .client import UserDataAPIClient
from .config import UserDataEvent, UserDataStatus
from .errors import LocalUserNotFoundError, NoIDPFoundError, UserCreationFailed
from .proxies import (
    current_names_sync_service,
    current_record_kc_username_sync_service,
    current_remote_group_service,
    current_remote_user_data_service,
)
from .types.auth import AccountInfo
from .types.profiles_api import APIResponse
from .utils.auth import CILogonHelpers, UserIdentifierHelpers

USER_DATA_UPDATE_LOCK_SUFFIX = "user-data-updating"
USER_DATA_CREATED_LOCK_SUFFIX = "user-created-updating"
GROUP_DATA_UPDATE_LOCK_SUFFIX = "group-data-updating"


def update_lock_backoff_seconds(attempt: int) -> float:
    """Seconds to sleep before lock retry attempt ``attempt`` (0-based).

    Uses progressive backoff: ``initial_backoff + (attempt * backoff_step)``.

    Returns:
        Delay in seconds before the next lock acquire attempt.
    """
    return app.config["REMOTE_USER_DATA_UPDATE_LOCK_INITIAL_BACKOFF"] + (
        attempt * app.config["REMOTE_USER_DATA_UPDATE_LOCK_BACKOFF_STEP"]
    )


class UpdateLockNotHeld(Exception):
    """Raised when entering a lock context without ``held`` status."""


class UserUpdateLock:
    """Per-entity mutex lock backed by Redis (``invenio_cache``)."""

    def __init__(self, key_suffix: str) -> None:
        """Initialize a lock scoped to keys ending with ``key_suffix``."""
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
        """Return self when the lock was acquired.

        Raises:
            UpdateLockNotHeld: If ``acquire`` did not set ``status`` to ``held``.
        """
        if self.status != "held":
            raise UpdateLockNotHeld(f"Cannot acquire lock with status {self.status!r}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        """Release the lock and do not suppress task exceptions.

        Returns:
            Always ``False`` so exceptions propagate from the guarded block.
        """
        self.release()
        return False


def with_update_task_lock(lock_id_resolver: Callable, key_suffix: str):
    """Decorator that acquires a per-entity update lock before running a task.

    Returns:
        A wrapper that retries with backoff when the lock is held elsewhere.
    """

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
                    for _ in range(
                        app.config["REMOTE_USER_DATA_UPDATE_LOCK_MAX_RETRIES"]
                    ):
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
                return func(*args, **kwargs)

        return wrapper

    return decorator


def _user_created_lock_id(_self, _idp: str, *args, **kwargs) -> str:
    """Resolve the per-entity lock key for ``do_user_created``.

    Uses ``kc_username`` (members webhook path) or ``oauth_id`` (subs path).

    Returns:
        The lock id string.

    Raises:
        ValueError: If neither ``kc_username`` nor ``oauth_id`` is present.
    """
    kc_username = (kwargs.get("kc_username") or "").strip()
    if kc_username:
        return kc_username
    oauth_id = (kwargs.get("oauth_id") or "").strip()
    if oauth_id:
        return oauth_id
    raise ValueError(
        "do_user_created lock requires kc_username or oauth_id"
    )


def _retry_at_iso(seconds_from_now: int) -> str:
    """Return an ISO 8601 UTC timestamp `seconds_from_now` in the future.

    Used to populate the `retry_at` field on FAILED status callbacks
    so the Profiles side can tell that another attempt is already
    scheduled and avoid prompting an operator for manual remediation.

    Args:
        seconds_from_now: Number of seconds in the future at which the
            next attempt is scheduled.

    Returns:
        An ISO 8601 UTC timestamp (e.g. `"2026-04-21T15:30:00+00:00"`).
    """
    return (datetime.now(UTC) + timedelta(seconds=seconds_from_now)).isoformat()


def _send_status(
    status: UserDataStatus,
    event: UserDataEvent,
    *,
    kc_username: str | None = None,
    sub: str | None = None,
    user: User | None = None,
    method: str | None = None,
    retry_at: str | None = None,
    note: str | None = None,
) -> None:
    """Best-effort wrapper around the Profiles status callback.

    The KC member name routes the callback URL
    (`/api/v1/members/{username or "unknown"}/works/status`). When
    `kc_username` is not supplied it is resolved from `user` (preferred)
    or from `UserIdentity(method, id=sub)`. The OAuth `sub` in the JSON
    body is optional correlation (`null` for members-only users).

    The callback is skipped with a warning when neither `kc_username`
    nor `sub` is supplied.

    Args:
        status: `UserDataStatus` member.
            `UserDataStatus.PROCESSED` or `UserDataStatus.FAILED`.
        event: `UserDataEvent` member, mirroring the inbound webhook
            `event` field.
        kc_username: KC member name when already known (e.g. username-based
            webhook path).
        sub: The OAuth `sub` (`UserIdentity.id`), or `None`.
        user: Optional local `User` to read the member name from
            without an extra `UserIdentity` lookup.
        method: Optional `UserIdentity.method` to disambiguate the
            sub lookup when `user` is not supplied.
        retry_at: Optional ISO 8601 UTC timestamp when a follow-up
            attempt is already scheduled.
        note: Optional freeform diagnostic string.
    """
    if not kc_username and not sub:
        # Neither identifier can route or correlate the callback.
        app.logger.warning(
            "_send_status: missing kc_username and sub; skipping (status=%s event=%s)",
            status,
            event,
        )
        return

    username = kc_username
    if not username and user is not None:
        username = UserIdentifierHelpers.username_from_user(user)
    if not username and sub:
        username = UserIdentifierHelpers.resolve_kc_username(sub, user, method=method)

    try:
        UserDataAPIClient.send_user_status_callback(
            sub=sub,
            username=username,
            status=status,
            event=event,
            retry_at=retry_at,
            note=note,
        )
    except Exception:
        # The client method already does inline retry + logging; a
        # surprise exception here must not bubble out of the task body.
        app.logger.warning(
            "send_user_status_callback raised unexpectedly for "
            "sub=%s username=%s status=%s event=%s",
            sub,
            username,
            status,
            event,
            exc_info=True,
        )


def _reschedule_callback_context(
    reschedule_task,
    reschedule_args: tuple,
    reschedule_kwargs: dict,
) -> tuple[
    str | None,
    str | None,
    str | None,
    UserDataEvent,
    bool,
]:
    """Derive status-callback fields from a long-delay reschedule payload.

    Returns:
        Tuple of ``sub``, ``method``, ``kc_username``, ``event``,
        ``send_status_callback``.
    """
    send_status_callback = reschedule_kwargs.get("send_status_callback", True)
    event = reschedule_kwargs.get("status_event", UserDataEvent.UPDATED)
    if isinstance(event, str):
        event = UserDataEvent(event)
    kc_username = reschedule_kwargs.get("kc_username")

    task_name = getattr(reschedule_task, "name", "") or ""
    if task_name.endswith("do_user_data_update"):
        sub = reschedule_args[2] if len(reschedule_args) > 2 else None
        method = reschedule_args[1] if len(reschedule_args) > 1 else None
    else:
        sub = reschedule_kwargs.get("oauth_id")
        method = reschedule_kwargs.get("callback_method")
        if method is None and reschedule_args:
            method = reschedule_args[0]

    return sub, method, kc_username, event, send_status_callback


def _handle_profiles_api_failure(
    self,
    exc: Exception,
    *,
    reschedule_task,
    reschedule_args: tuple,
    reschedule_kwargs: dict,
) -> None:
    """Apply the shared HTTP retry + long-delay reschedule policy.

    Both `do_user_created` and `do_user_data_update` need the same
    behaviour when the Profiles API is unreachable
    (`requests.RequestException` / `requests.Timeout`):

    1. Send a FAILED status callback with a `retry_at` timestamp so
       the Profiles operator can see another attempt is already
       scheduled.
    2. Trigger Celery's bounded retry mechanism with exponential
       backoff (30s, 60s, 120s, 240s, 480s, capped at 600s). This
       raises a `Retry` exception which propagates out of this
       helper, out of the calling task, and Celery handles it.
    3. When the bounded retry budget is exhausted Celery raises
       `MaxRetriesExceededError` synchronously from `self.retry`;
       we catch it here, log an error, send a final FAILED callback
       with a far-future `retry_at`, and re-enqueue the task with a
       long countdown
       (`REMOTE_USER_DATA_USER_CREATED_RESCHEDULE_DELAY`, default
       1 hour, shared by both tasks).

    Control flow
    ------------

    The helper either:

    * raises `Retry` (the normal retry path -- exits the calling
      task, Celery handles re-execution), **or**
    * returns normally (the long-delay reschedule path -- the calling
      task should `return` immediately so it doesn't try to
      continue work after the reschedule has been queued).

    Status callbacks read ``sub``, ``method``, ``kc_username``, ``event``,
    and ``send_status_callback`` from ``reschedule_kwargs`` and
    ``reschedule_args`` (see `_reschedule_callback_context`).

    Args:
        self: The bound Celery task instance (caller passes its own
            `self`). Used for `self.request.retries`,
            `self.retry`, `self.max_retries`, and `self.name`.
        exc: The HTTP exception that triggered this call.
        reschedule_task: The Celery task object to re-enqueue
            (typically the calling task itself).
        reschedule_args: Positional `args` tuple to pass to
            `reschedule_task.apply_async` on the long-delay
            reschedule path.
        reschedule_kwargs: Keyword args for the long-delay
            reschedule; also supplies callback context
            (`kc_username`, `oauth_id`, `status_event`,
            `send_status_callback`, `callback_method` for
            `do_user_created`).
    """
    sub, method, kc_username, event, send_status_callback = (
        _reschedule_callback_context(
            reschedule_task, reschedule_args, reschedule_kwargs
        )
    )
    retries = self.request.retries or 0
    countdown = min(30 * (2**retries), 600)
    try:
        if send_status_callback:
            _send_status(
                UserDataStatus.FAILED,
                event,
                kc_username=kc_username,
                sub=sub,
                method=method,
                retry_at=_retry_at_iso(countdown),
                note=f"profiles_api:{type(exc).__name__}",
            )
        raise self.retry(exc=exc, countdown=countdown)
    except MaxRetriesExceededError:
        long_delay = int(
            app.config.get(
                "REMOTE_USER_DATA_USER_CREATED_RESCHEDULE_DELAY",
                3600,
            )
        )
        app.logger.error(
            "%s: exhausted %s retries for sub=%s (%r); rescheduling in %ss",
            self.name,
            self.max_retries,
            sub,
            exc,
            long_delay,
        )
        if send_status_callback:
            _send_status(
                UserDataStatus.FAILED,
                event,
                kc_username=kc_username,
                sub=sub,
                method=method,
                retry_at=_retry_at_iso(long_delay),
                note=(
                    f"profiles_api:{type(exc).__name__}:retries_exhausted_rescheduled"
                ),
            )
        reschedule_task.apply_async(
            args=reschedule_args,
            kwargs=reschedule_kwargs,
            countdown=long_delay,
        )


@shared_task(
    bind=True,
    ignore_result=True,
    max_retries=5,
)
@with_update_task_lock(
    lock_id_resolver=lambda self, user_id, *args, **kwargs: int(user_id),
    key_suffix=USER_DATA_UPDATE_LOCK_SUFFIX,
)
def do_user_data_update(
    self,
    user_id: int,
    idp: str | None = None,
    remote_id: str | None = None,
    kc_username: str | None = None,
    remote_data: APIResponse | None = None,
    send_status_callback: bool = True,
    status_event: UserDataEvent = UserDataEvent.UPDATED,
    **kwargs,
) -> tuple[User, dict, list[str], dict] | None:
    """Perform a user metadata update.

    Profiles fetch needs `kc_username` or `remote_id` (OAuth `sub`).
    Webhook callers pass `user_id`, `idp`, and `kc_username` (members
    endpoint). Login callers pass `user_id` only; omitting `idp`
    triggers a `UserIdentity` lookup that sets `remote_id` (subs
    endpoint).

    When `send_status_callback` is True (default), the task sends
    PROCESSED/FAILED callbacks to Profiles on completion or failure.
    Login enqueue passes `send_status_callback=False`.

    Status callback
    ---------------

    Callbacks target
    `/api/v1/members/{member_name}/works/status`. The KC member name
    for the URL and body is resolved locally (`kc_username`, the local
    user row, or `UserIdentity`). When no member name can be resolved
    the callback still fires with `unknown` in the URL so the Profiles
    operator can correlate by optional `sub` in the response body.

    After update, we also keep the user's Names vocabulary record in
    sync with their just-updated profile. Failures in this vocabulary sync
    are logged but never break the user-data update path.

    Failure handling
    ----------------

    Transient HTTP failures while fetching the Profiles API
    (`requests.RequestException` / `requests.Timeout`) propagate
    out of `service.update_user_from_remote` and are caught here.
    They are routed through the shared
    `_handle_profiles_api_failure()` helper, which applies the
    same bounded exponential-backoff retry (30s, 60s, 120s, …, capped
    at 600s) that `do_user_created` uses; on exhaustion the task is
    re-enqueued with a long countdown
    (`REMOTE_USER_DATA_USER_CREATED_RESCHEDULE_DELAY`, shared
    config key). When `send_status_callback` is True, FAILED
    callbacks include a `retry_at` timestamp so the Profiles
    operator can see another attempt is pending.

    Other unexpected exceptions trigger a FAILED callback when
    `send_status_callback` is True and are re-raised so Celery
    surfaces the error.

    Args:
        self: The bound Celery task instance, used by
            `_handle_profiles_api_failure()` for `self.retry`.
        user_id: The local ID of the user to update.
        idp: Remote service key. Webhook callers pass this; login omits
            it so the task can resolve `UserIdentity`.
        remote_id: OAuth `sub`. Webhook callers omit this (use
            `kc_username` instead). Login path: set from `UserIdentity`.
        kc_username: KC member name. Webhook callers pass this. Login
            callers omit this (use `remote_id` instead).
        remote_data: Optional pre-fetched Profiles subs payload. When set,
            passed through to `update_user_from_remote` instead of fetching.
        send_status_callback: Send PROCESSED/FAILED callbacks to
            Profiles. Defaults to True; False on login enqueue.
        status_event: Profiles status-callback `event` field. Defaults to
            `updated`; `do_user_created` delegates with `created`.
        **kwargs: Reserved for future Celery options; forwarded
            unchanged to the long-delay reschedule path.

    Raises:
        LocalUserNotFoundError: If the local user row is missing during
            `update_user_from_remote`.
        NoIDPFoundError: If the user has no resolvable remote identity
            provider.

    Returns:
        Plain dict summarizing the run (IDs, group names, group deltas, and
        optional user-field changes when the service returns a dict). Safe for
        Celery's JSON result backend; not the raw service tuple.
    """
    with app.app_context():
        if isinstance(status_event, str):
            status_event = UserDataEvent(status_event)

        if not idp:
            my_user_identity = UserIdentity.query.filter_by(
                id_user=user_id, method=idp or "cilogon"
            ).first()
            # will have a UserIdentity if the user has logged in via an IDP
            if my_user_identity is not None:
                idp = my_user_identity.method
                remote_id = my_user_identity.id

        if not idp:
            user = datastore.get_user_by_id(user_id)
            if send_status_callback:
                _send_status(
                    UserDataStatus.FAILED,
                    status_event,
                    kc_username=kc_username,
                    sub=remote_id,
                    user=user,
                    note="NoIDPFoundError",
                )
            raise NoIDPFoundError(f"No IDP found for user {user_id}")

        service = current_remote_user_data_service
        try:
            user, updated_data, groups, groups_changes = (
                service.update_user_from_remote(
                    system_identity,
                    user_id,
                    idp,
                    remote_id=remote_id,
                    kc_username=kc_username,
                    remote_data=remote_data,
                )
            )
            app.logger.debug("returned from task user update")
        except (requests.RequestException, requests.Timeout) as exc:
            app.logger.warning(
                "do_user_data_update: Profiles API failure for user_id=%s sub=%s: %r",
                user_id,
                remote_id,
                exc,
            )
            _handle_profiles_api_failure(
                self,
                exc,
                reschedule_task=do_user_data_update,
                reschedule_args=(user_id, idp, remote_id),
                reschedule_kwargs={
                    **kwargs,
                    "kc_username": kc_username,
                    "remote_data": remote_data,
                    "status_event": status_event,
                    "send_status_callback": send_status_callback,
                },
            )
            # Only reached on the long-delay reschedule branch; the
            # normal retry branch raises `Retry` out of the helper.
            return None
        except LocalUserNotFoundError as exc:
            app.logger.error(
                "do_user_data_update: local user missing (%s); "
                "user_id=%s idp=%s remote_id=%s",
                exc,
                user_id,
                idp,
                remote_id,
            )
            user = datastore.get_user_by_id(user_id)
            if send_status_callback:
                _send_status(
                    UserDataStatus.FAILED,
                    status_event,
                    kc_username=kc_username,
                    sub=remote_id,
                    user=user,
                    method=idp,
                    note="LocalUserNotFoundError",
                )
            raise
        except Exception as exc:
            user = datastore.get_user_by_id(user_id)
            if send_status_callback:
                _send_status(
                    UserDataStatus.FAILED,
                    status_event,
                    kc_username=kc_username,
                    sub=remote_id,
                    user=user,
                    method=idp,
                    note=type(exc).__name__,
                )
            raise

        if user is not None:
            app.logger.debug("syncing names")
            sync_user_to_names.delay(user.id)

        if send_status_callback:
            _send_status(
                UserDataStatus.PROCESSED,
                status_event,
                kc_username=kc_username,
                sub=remote_id,
                user=user,
                method=idp,
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


def _enqueue_user_data_update(
    user_id: int,
    idp: str,
    remote_id: str | None = None,
    *,
    kc_username: str | None = None,
    remote_data: APIResponse | None = None,
    send_status_callback: bool = True,
    status_event: UserDataEvent = UserDataEvent.UPDATED,
    run_synchronously: bool = False,
) -> None:
    """Queue or run ``do_user_data_update`` for a local user.

    Webhook paths use ``delay``; ingest passes ``run_synchronously=True``
    so ``apply`` runs the update inline before the ingest row returns.
    """
    update_kwargs = {
        "kc_username": kc_username,
        "remote_data": remote_data,
        "send_status_callback": send_status_callback,
        "status_event": status_event,
    }
    if run_synchronously:
        do_user_data_update.apply(
            args=(user_id, idp, remote_id),
            kwargs=update_kwargs,
        )
    else:
        do_user_data_update.delay(user_id, idp, remote_id, **update_kwargs)


@shared_task(ignore_result=True)
@with_update_task_lock(
    lock_id_resolver=lambda user_id, *args, **kwargs: int(user_id),
    key_suffix=USER_DATA_UPDATE_LOCK_SUFFIX,
)
def do_user_associated(
    user_id: int,
    idp: str,
    oauth_id: str,
    auth_method: str,
    kc_username: str | None = None,
    send_status_callback: bool = True,
    **kwargs,
) -> dict[str, Any]:
    """Link a remote OAuth identity to a KC user and sync profile data.

    Triggered by ``associations`` / ``associated`` webhook events when Profiles
    links a CILogon ``sub`` to an existing KC member account.

    When ``send_status_callback`` is True (default), the task sends
    PROCESSED/FAILED callbacks to Profiles with ``event=associated``,
    mirroring ``do_user_data_update``.

    Args:
        user_id: The local ID of the user to update.
        idp: The remote service configuration key (e.g. ``knowledgeCommons``).
        oauth_id: The OAuth/CILogon subject identifier to associate.
        auth_method: The ``UserIdentity.method`` value (e.g. ``cilogon``).
        kc_username: KC member name for Profiles API lookup.
        send_status_callback: Send PROCESSED/FAILED callbacks to Profiles.
        **kwargs: Reserved for future Celery options.

    Returns:
        Plain dict summarizing the association and user update run.

    Raises:
        LocalUserNotFoundError: If the local user row is missing during sync.
        requests.RequestException: On transient Profiles API HTTP failures.
        requests.Timeout: On Profiles API request timeout.
    """
    status_event = UserDataEvent.ASSOCIATED

    with app.app_context():

        def _status(
            status: UserDataStatus,
            *,
            user: User | None = None,
            **send_kw,
        ) -> None:
            if send_status_callback:
                _send_status(
                    status,
                    status_event,
                    kc_username=kc_username,
                    sub=oauth_id,
                    user=user,
                    method=auth_method,
                    **send_kw,
                )

        user = db.session.get(User, user_id)
        if user is None:
            app.logger.error(
                "do_user_associated: local user missing; user_id=%s oauth_id=%s",
                user_id,
                oauth_id,
            )
            _status(UserDataStatus.FAILED, note="user_not_found")
            return {
                "user_id": user_id,
                "status": "error",
                "reason": "User not found",
            }

        existing_identity = UserIdentity.query.filter_by(
            method=auth_method, id=oauth_id
        ).first()
        if existing_identity is not None and existing_identity.id_user != user_id:
            app.logger.error(
                "Cannot associate oauth_id=%r with user_id=%s; already linked to "
                "user_id=%s",
                oauth_id,
                user_id,
                existing_identity.id_user,
            )
            _status(
                UserDataStatus.FAILED,
                user=user,
                note="oauth_identity_linked_to_other_user",
            )
            return {
                "user_id": user_id,
                "oauth_id": oauth_id,
                "status": "error",
                "reason": "OAuth identity already linked to another user",
            }

        CILogonHelpers.link_user_to_oauth_identifier(user, auth_method, oauth_id)

        service = current_remote_user_data_service
        try:
            user, updated_data, groups, groups_changes = (
                service.update_user_from_remote(
                    system_identity,
                    user_id,
                    idp,
                    remote_id=oauth_id,
                    kc_username=kc_username,
                )
            )
        except (requests.RequestException, requests.Timeout) as exc:
            app.logger.warning(
                "do_user_associated: Profiles API failure for user_id=%s sub=%s: %r",
                user_id,
                oauth_id,
                exc,
            )
            _status(
                UserDataStatus.FAILED,
                user=user,
                note=f"profiles_api:{type(exc).__name__}",
            )
            raise
        except LocalUserNotFoundError as exc:
            app.logger.error(
                "do_user_associated: local user missing (%s); user_id=%s sub=%s",
                exc,
                user_id,
                oauth_id,
            )
            _status(UserDataStatus.FAILED, user=user, note="LocalUserNotFoundError")
            raise
        except Exception as exc:
            _status(UserDataStatus.FAILED, user=user, note=type(exc).__name__)
            raise

        if user is not None:
            sync_user_to_names.delay(user.id)

        _status(UserDataStatus.PROCESSED, user=user)

        summary: dict[str, Any] = {
            "user_id": user_id,
            "idp": idp,
            "auth_method": auth_method,
            "remote_id": oauth_id,
            "kc_username": kc_username,
            "completed_user_id": user.id if user is not None else None,
            "groups": list(groups),
            "group_changes": dict(groups_changes)
            if isinstance(groups_changes, dict)
            else {},
            "status": "associated",
        }
        if isinstance(updated_data, dict):
            summary["user_field_changes"] = updated_data
        encoded = json.dumps(summary, default=str)
        return json.loads(encoded)


@shared_task(ignore_result=False)
@with_update_task_lock(
    lock_id_resolver=lambda idp, remote_id, *args, **kwargs: f"{idp}:{remote_id}",
    key_suffix=GROUP_DATA_UPDATE_LOCK_SUFFIX,
)
def do_group_data_update(idp, remote_id, **kwargs):
    """Perform a group metadata update.

    Returns:
        `True` when the update completed successfully.
    """
    with app.app_context():
        service = current_remote_group_service
        service.update_group_from_remote(system_identity, idp, remote_id)
        return True


@shared_task(ignore_result=False)
def do_find_names_duplicates(
    limit: int | None = None,
    since: datetime | None = None,
    full_sweep: bool = False,
):
    """Find possible duplicate entries in the Names vocabulary.

    Returns:
        The duplicate-candidate rows returned by the names-sync service.
    """
    with app.app_context():
        result = current_names_sync_service.find_duplicate_candidates(
            limit=limit, since=since, full_sweep=full_sweep
        )
        return result


@shared_task(
    bind=True,
    ignore_result=False,
    max_retries=5,
)
@with_update_task_lock(
    lock_id_resolver=_user_created_lock_id,
    key_suffix=USER_DATA_CREATED_LOCK_SUFFIX,
)
def do_user_created(
    self,
    idp: str,
    *,
    oauth_id: str | None = None,
    remote_data: APIResponse | None = None,
    kc_username: str | None = None,
    update_existing: bool = True,
    send_status_callback: bool = True,
    run_synchronously: bool = False,
    resolve_sub_from_username: bool = False,
    **kwargs,
) -> int | None:
    """Provision a local KCWorks user from a remote ``created`` signal.

    Triggered from
    `invenio_remote_user_data_kcworks.services.service.RemoteUserDataService`
    when a `users.created` webhook event is consumed from the
    `user-data-updates` queue, and reused by username-list rows in
    `do_ingest_profiles_dump`.

    Routes on identifiers (at least one required):

    1. Neither ``kc_username`` nor ``oauth_id`` — optional FAILED callback,
       return.
    2. ``oauth_id`` present (subs path; ``kc_username`` optional) — fetch or
       use pre-fetched subs payload, match/create local `User`, ensure
       `UserIdentity` (idempotent), delegate to `do_user_data_update`.
    3. ``kc_username`` only (members path) — find or provision from
       ``members/{kc_username}/`` (no `UserIdentity`; PROCESSED callback
       from this task on success).

    Idempotent when ``update_existing`` is True (default): an existing local
    user (by `UserIdentity` on the subs path or KC username on the members
    path) delegates to `do_user_data_update` without a duplicate callback
    from this task. Ingest passes ``update_existing=False``; an existing
    ``identifier_kc_username`` row returns ``None`` before any Profiles I/O.

    Failure handling
    ----------------

    Transient HTTP failures on the subs **profile fetch** use
    `_handle_profiles_api_failure()` (bounded exponential backoff, then
    long-delay reschedule via `REMOTE_USER_DATA_USER_CREATED_RESCHEDULE_DELAY`,
    shared with `do_user_data_update`). Follow-up `update_user_from_remote`
    failures are handled inside the delegated `do_user_data_update` task.

    Status callback
    ---------------

    When ``send_status_callback`` is True (default), this task emits
    PROCESSED/FAILED on give-up paths here (missing identifiers, no profile
    data, user match/create failure, members provision failure). Subs-path
    success and delegated updates rely on `do_user_data_update` for PROCESSED.
    Scheduled retries/reschedules include `retry_at` in FAILED callbacks.
    Ingest passes ``send_status_callback=False``.

    Args:
        self: Bound Celery task instance (subs fetch retries only).
        idp: Remote service key (e.g. ``knowledgeCommons``); matches a key
            in `REMOTE_USER_DATA_API_ENDPOINTS`.
        oauth_id: OAuth ``sub`` (`UserIdentity.id`) when linked on Profiles.
        remote_data: Optional pre-fetched Profiles subs payload for
            ``oauth_id``. Skips the live fetch; used by JSONL ingest replay.
            Ignored on the existing-`UserIdentity` short-circuit when
            ``update_existing`` is True.
        kc_username: KC member name (required on members-only path).
        update_existing: When True (default), existing users delegate to
            ``do_user_data_update``. When False, return ``None``.
        send_status_callback: Emit PROCESSED/FAILED callbacks from this task
            and pass through to ``do_user_data_update``.
        run_synchronously: Run ``do_user_data_update`` via ``apply`` instead
            of ``delay`` (ingest).
        resolve_sub_from_username: When True and ``oauth_id`` is omitted,
            try ``GET subs/{kc_username}/`` before the members path
            (username-list ingest only).
        **kwargs: Forwarded on subs-fetch reschedule.

    Raises:
        LocalUserNotFoundError: Propagated from delegated
            ``do_user_data_update`` when the local user row is missing.

    Returns:
        Local user id, or ``None`` on give-up, ingest skip, or subs-fetch
        reschedule.
    """
    with app.app_context():
        kc_username = (kc_username or "").strip()
        oauth_id = (oauth_id or "").strip() or None
        service = current_remote_user_data_service

        if not update_existing and kc_username:
            if service.find_local_user_by_kc_username(kc_username) is not None:
                return None

        if not oauth_id and kc_username and resolve_sub_from_username:
            subs_payload = service.fetch_subs_profile_for_kc_username(kc_username)
            if subs_payload is not None and subs_payload.data:
                oauth_id = subs_payload.data[0].sub
                if remote_data is None:
                    remote_data = subs_payload

        def _status(
            status: UserDataStatus,
            event: UserDataEvent = UserDataEvent.CREATED,
            **send_kw,
        ) -> None:
            if send_status_callback:
                _send_status(status, event, **send_kw)

        def _delegate_update(
            user_id: int,
            *,
            sub: str | None = None,
            profile_data: APIResponse | None = None,
        ) -> None:
            _enqueue_user_data_update(
                user_id,
                idp,
                sub,
                kc_username=kc_username or None,
                remote_data=profile_data,
                send_status_callback=send_status_callback,
                status_event=UserDataEvent.CREATED,
                run_synchronously=run_synchronously,
            )

        reschedule_kw = {
            **kwargs,
            "oauth_id": oauth_id,
            "kc_username": kc_username,
            "update_existing": update_existing,
            "send_status_callback": send_status_callback,
            "run_synchronously": run_synchronously,
            "resolve_sub_from_username": resolve_sub_from_username,
            "status_event": UserDataEvent.CREATED,
            **({"remote_data": remote_data} if remote_data is not None else {}),
        }

        if not kc_username and not oauth_id:
            app.logger.warning(
                "do_user_created: missing kc_username and oauth_id; skipping"
            )
            _status(UserDataStatus.FAILED, note="missing_identifiers")
            return None

        if oauth_id:
            auth_method = idp
            if idp == "knowledgeCommons":
                kc_idps = app.config.get("KC_REMOTE_IDPS") or []
                if kc_idps:
                    auth_method = kc_idps[0]
            reschedule_kw["callback_method"] = auth_method

            existing = UserIdentity.query.filter_by(
                id=oauth_id, method=auth_method
            ).one_or_none()
            if existing is not None:
                app.logger.debug(
                    "do_user_created: UserIdentity already exists for "
                    f"sub={oauth_id} method={auth_method}; delegating to "
                    "do_user_data_update"
                )
                if not update_existing:
                    return None
                _delegate_update(
                    existing.id_user,
                    sub=oauth_id,
                    profile_data=remote_data,
                )
                return existing.id_user

            if remote_data is not None:
                profile_response = remote_data
            else:
                try:
                    profile_response = UserDataAPIClient.fetch_user_profile(
                        sub_id=oauth_id
                    )
                except (requests.RequestException, requests.Timeout) as exc:
                    app.logger.warning(
                        f"do_user_created: failed to fetch profile for "
                        f"sub={oauth_id}: {exc!r}"
                    )
                    _handle_profiles_api_failure(
                        self,
                        exc,
                        reschedule_task=do_user_created,
                        reschedule_args=(idp,),
                        reschedule_kwargs=reschedule_kw,
                    )
                    # Only reached on the long-delay reschedule branch.
                    return None

            if not profile_response or not getattr(profile_response, "data", None):
                app.logger.info(
                    f"do_user_created: no profile data returned for "
                    f"sub={oauth_id}; skipping user creation"
                )
                _status(
                    UserDataStatus.FAILED,
                    sub=oauth_id,
                    kc_username=kc_username or None,
                    method=auth_method,
                    note="no_profile_data",
                )
                return None

            # Match an existing user if possible; a user may have previously
            # logged in with a different method.
            profile = profile_response.data[0].profile
            account_info = AccountInfo(
                external_id=oauth_id,
                external_method=auth_method,
                email=(profile.email or ""),
                orcid=profile.orcid,
                kc_username=(profile.username or ""),
            )
            user = CILogonHelpers.get_user_from_account_info(account_info)
            if user is None:
                try:
                    user = CILogonHelpers.create_new_user(profile_response)
                except IntegrityError:
                    # Race-loser path: a concurrent `do_user_created` for
                    # the same sub committed the `User` row first, so the
                    # upstream `register_user` INSERT hit the unique
                    # constraint on email/username. Roll back so the
                    # SQLAlchemy session is usable again, then re-match
                    # exactly once. If the re-match still produces no
                    # user, the IntegrityError isn't a race -- it's a
                    # data inconsistency we can't safely recover from in
                    # this task, so we FAIL cleanly without looping.
                    db.session.rollback()
                    app.logger.warning(
                        "do_user_created: IntegrityError during "
                        "create_new_user for sub=%s; re-matching after "
                        "rollback",
                        oauth_id,
                    )
                    user = CILogonHelpers.get_user_from_account_info(account_info)
                    if user is None:
                        app.logger.error(
                            "do_user_created: IntegrityError on create "
                            "and re-match still produced no user for "
                            "sub=%s; giving up",
                            oauth_id,
                        )
                        _status(
                            UserDataStatus.FAILED,
                            sub=oauth_id,
                            kc_username=kc_username or None,
                            method=auth_method,
                            note="integrity_error_unresolved",
                        )
                        return None
                except UserCreationFailed:
                    app.logger.warning(
                        "do_user_created task: UserCreationFailed during "
                        "create_new_user for sub=%s",
                        oauth_id,
                    )
                    _status(
                        UserDataStatus.FAILED,
                        sub=oauth_id,
                        kc_username=kc_username or None,
                        method=auth_method,
                        note="user_creation_failed",
                    )
                    return None

            if user is None:
                app.logger.warning(
                    f"do_user_created: could not find or create user for "
                    f"sub={oauth_id}"
                )
                _status(
                    UserDataStatus.FAILED,
                    sub=oauth_id,
                    kc_username=kc_username or None,
                    method=auth_method,
                    note="user_match_or_create_failed",
                )
                return None

            with contextlib.suppress(AlreadyLinkedError):
                CILogonHelpers.link_user_to_oauth_identifier(
                    user, auth_method, oauth_id
                )

            # Run the normal update path so user_profile fields and group
            # memberships are populated from the same payload we already
            # fetched. HTTP failures there get retry+reschedule inside
            # `do_user_data_update`. A re-run of this task will short-circuit
            # through the existing-identity branch and delegate again.
            _delegate_update(
                user.id,
                sub=oauth_id,
                profile_data=profile_response,
            )
            return user.id

        # Members-only: `kc_username` with no `oauth_id`.
        existing_user = service.find_local_user_by_kc_username(kc_username)
        if existing_user is not None:
            # Same delegated callback policy as the subs identity branch.
            _delegate_update(existing_user.id)
            return existing_user.id
        user = service.provision_user_from_members_profile(
            system_identity, kc_username, idp=idp
        )
        if user is None:
            _status(
                UserDataStatus.FAILED,
                kc_username=kc_username,
                note="provision_user_from_members_profile_failed",
            )
            return None
        # Members-only success does not call `do_user_data_update`; sync Names
        # here (subs-path success delegates to update, which syncs there).
        sync_user_to_names.delay(user.id)
        _status(
            UserDataStatus.PROCESSED,
            kc_username=kc_username,
            user=user,
        )
        return user.id


@shared_task(ignore_result=False)
def rewrite_records_for_kc_username_change(
    user_id: int,
    old_kc_username: str,
    new_kc_username: str,
) -> dict[str, Any]:
    """Propagate a Profiles-side kc_username rename through RDM records.

    Dispatched from `RemoteUserDataService.update_user_from_remote` when the
    committed user's `identifier_kc_username` differs from its pre-update
    value. Runs three steps in sequence; each is wrapped in its own
    try/except so a failure in one phase does not skip the others.

    1. Published records pass — `RecordKcUsernameSyncService.rewrite` (with
       `drafts=False`) opens a draft for each matching published record,
       rewrites creators+contributors, and re-publishes. Re-publish triggers
       normal publish-time hooks (DataCite, remote-API provisioner, stats);
       this is the same path a manual edit would take.
    2. Drafts pass — `RecordKcUsernameSyncService.rewrite` (with `drafts=True`)
       patches in-progress drafts with `update_draft` (no auto-publish; their
       owner may still be editing).
    3. Names prune — `NamesSyncService.prune_stale_user_records` deletes any
       Names vocabulary records still sitting at the user's previous PID.
       The new PID is upserted by the existing `sync_user_to_names` task
       that `do_user_data_update` already fires; this step only removes
       what's stale, so ordering against `sync_user_to_names` doesn't
       matter.

    Args:
        user_id: The local Invenio user id that was renamed.
        old_kc_username: The pre-rename KC username.
        new_kc_username: The post-rename KC username.

    Returns:
        Stats dict aggregating both rewrite passes and the Names prune.
        Top-level keys:

        - `user_id`, `old_kc_username`, `new_kc_username`: echo of inputs.
        - `records`: stats from `RecordKcUsernameSyncService.rewrite_all`.
        - `pruned_names_pids`: list of Names PIDs deleted by the prune step.
        - `errors`: count of top-level phase failures (per-record failures
          are reported inside `records`).
    """
    with app.app_context():
        summary: dict[str, Any] = {
            "user_id": user_id,
            "old_kc_username": old_kc_username,
            "new_kc_username": new_kc_username,
            "records": {},
            "pruned_names_pids": [],
            "errors": 0,
        }

        if (
            not old_kc_username
            or not new_kc_username
            or old_kc_username == new_kc_username
        ):
            app.logger.warning(
                "rewrite_records_for_kc_username_change: refusing to run "
                "with old=%r new=%r (must be non-empty and distinct)",
                old_kc_username,
                new_kc_username,
            )
            return summary

        try:
            summary["records"] = current_record_kc_username_sync_service.rewrite_all(
                old_kc_username, new_kc_username
            )
        except Exception:  # noqa: BLE001 - logged, never propagated
            summary["errors"] += 1
            app.logger.exception(
                "rewrite_records_for_kc_username_change: records rewrite "
                "phase raised for user_id=%s old=%s new=%s",
                user_id,
                old_kc_username,
                new_kc_username,
            )

        try:
            user = datastore.get_user_by_id(user_id)
            if user is None:
                app.logger.warning(
                    "rewrite_records_for_kc_username_change: user %s not "
                    "found at prune time; skipping Names prune",
                    user_id,
                )
            else:
                summary["pruned_names_pids"] = (
                    current_names_sync_service.prune_stale_user_records(user)
                )
        except Exception:  # noqa: BLE001 - logged, never propagated
            summary["errors"] += 1
            app.logger.exception(
                "rewrite_records_for_kc_username_change: Names prune phase "
                "raised for user_id=%s old=%s new=%s",
                user_id,
                old_kc_username,
                new_kc_username,
            )

        return summary


@shared_task(ignore_result=True)
def sync_user_to_names(user_id: int) -> bool:
    """Mirror a single local user into the Names vocabulary.

    Thin Celery wrapper around
    `NamesSyncService.upsert_name_for_user()`. Used both as a
    side effect of the user create/update flows and directly from the
    `flask user-data names sync-now` CLI helper.

    Args:
        user_id: The local Invenio user id to mirror.

    Returns:
        `True` when a Names record was upserted (or already up to
        date), `False` when the user was missing or did not have
        enough profile data to be mirrored.
    """
    with app.app_context():
        app.logger.debug(f"syncing user to names: {user_id}")
        user = datastore.get_user_by_id(user_id)
        if user is None:
            app.logger.warning(
                f"sync_user_to_names: user {user_id} not found; skipping"
            )
            return False
        result = current_names_sync_service.upsert_name_for_user(user)
        app.logger.debug(f"result of name sync is {result}")
        return result is not None


def _sniff_dump_format(filepath: str) -> str:
    """Detect whether a file is JSONL (Profiles-shape) or a one-column CSV of usernames.

    The detection is intentionally cheap: read the first non-blank line, strip,
    and check whether it starts with `{`. Anything else is assumed to be a
    plain-text username list (one username per line; CSV header optional).

    Args:
        filepath: Path to the file to inspect.

    Returns:
        Either `"jsonl"` or `"usernames"`.
    """
    with open(filepath, encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            return "jsonl" if stripped.startswith("{") else "usernames"
    return "usernames"


def _iter_jsonl_rows(filepath: str, offset: int):
    """Yield ``(line_number, parsed_json)`` from a JSONL file, skipping blank lines.

    ``line_number`` is the 1-based physical line number in the source file.
    """
    with open(filepath, encoding="utf-8") as f:
        for line_no, raw in enumerate(islice(f, offset - 1, None), start=offset):
            line = raw.strip()
            if not line:
                continue
            yield line_no, json.loads(line)


def _iter_username_rows(filepath: str, offset: int):
    """Yield ``(line_number, username)`` from a one-column file, skipping blanks and comments.

    ``line_number`` is the 1-based physical line number in the source file.
    """
    with open(filepath, encoding="utf-8") as f:
        for line_no, raw in enumerate(islice(f, offset - 1, None), start=offset):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # Tolerate a CSV-style header row labelled "username" (case-insensitive).
            if line.lower() in {"username", '"username"'}:
                continue
            # If somebody hands us a CSV with extra columns, take the first one.
            yield line_no, line.split(",", 1)[0].strip().strip('"')


def _pace_ingest_rows(
    *,
    last_row_started_at: float | None,
    rate_per_second: float,
) -> float:
    """Block until the next ingest row may start under a rows-per-second cap.

    Args:
        last_row_started_at: Monotonic timestamp when the previous row started,
            or `None` before the first row.
        rate_per_second: Maximum number of rows to start per second. `0` disables
            pacing (returns immediately). Fractional values are allowed (e.g.
            `0.5` = one row every 2 seconds).

    Returns:
        Monotonic timestamp marking when this row's processing started.

    Raises:
        ValueError: If `rate_per_second` is negative.
    """
    if rate_per_second < 0:
        raise ValueError(
            "do_ingest_profiles_dump: rate_per_second must be >= 0, "
            f"got {rate_per_second}"
        )
    if rate_per_second == 0:
        return time.monotonic()

    now = time.monotonic()
    if last_row_started_at is not None:
        min_interval = 1.0 / rate_per_second
        delay = last_row_started_at + min_interval - now
        if delay > 0:
            time.sleep(delay)
            now = time.monotonic()
    return now


@shared_task(ignore_result=False)
def do_ingest_profiles_dump(
    filepath: str,
    *,
    fmt: str = "auto",
    source: str = "knowledgeCommons",
    limit: int | None = None,
    rate_per_second: float = 2,
    offset: int = 1,
) -> dict[str, int]:
    """Bulk-create / update local users from a Profiles dump file.

    Two input shapes are accepted; the format is sniffed by default
    from the first non-blank line:

    - **JSONL** (`fmt="jsonl"`): each line is one Profiles API response
      payload (matching `APIResponse` from `...types.profiles_api`). For
      every row we call `do_user_created` with `remote_data=<row>`,
      `send_status_callback=False`, and `run_synchronously=True` so no
      live Profiles API I/O or status callbacks occur and each row's
      update finishes before the next line is processed.
    - **Usernames** (`fmt="usernames"`): one KC username per line (CSV
      header `username` and `#` comment lines tolerated). Each row calls
      `do_user_created` with ingest flags (skip existing rows, no
      callbacks, synchronous update, subs resolution from username).

    Both code paths run synchronously *inside this single task* so a
    long ingest is observable as one Celery entry rather than thousands
    of per-row tasks; this is friendlier to Profiles API rate limits and
    easier for operators to monitor / abort. For the `usernames` format,
    row starts are paced by `rate_per_second` (default 2 rows/s) via a
    sleep between rows. Pacing is skipped for `jsonl` (no live API I/O)
    and when `rate_per_second` is `0` (unlimited).

    The operation is idempotent provided Profiles API-served data does not
    change between runs. Already-existing KCWorks users simply have their
    metadata updated from the Profiles API.

    Args:
        filepath: Absolute path to the dump file. Read with UTF-8.
        fmt: `"auto"` (sniff), `"jsonl"`, or `"usernames"`.
        source: The IDP key to pass to `do_user_created`. Defaults to
            `"knowledgeCommons"`.
        limit: Maximum number of dump rows to process; `None` processes
            the entire file.
        rate_per_second: Maximum number of dump rows to start per second for
            the `usernames` format. A delay is inserted between row starts
            when processing would otherwise exceed this rate. `0` disables
            pacing. Fractional values are allowed (e.g. `0.5` = one row
            every 2 seconds). Ignored for `jsonl` ingest (no Profiles API
            calls).
        offset: Source document line number to begin with for the ingest.
            The first line is `1` (Not 0 indexed.) Default is 1, which is
            the first line of the file.

    Returns:
        A stats dict with keys:

        - `rows_seen`: number of non-blank rows in the file.
        - `processed`: rows that produced a non-`None` user id.
        - `skipped`: rows where `do_user_created` returned `None` (no
          profile data, missing oauth_id, etc.).
        - `errors`: rows that raised an exception (logged, not
          propagated, so the rest of the dump still runs).

    Raises:
        ValueError: When `fmt` is not one of `"auto"`, `"jsonl"`, or
            `"usernames"`, when `rate_per_second` is negative, or when
            `limit` is less than 1.
    """
    with app.app_context():
        if fmt == "auto":
            fmt = _sniff_dump_format(filepath)
        if fmt not in {"jsonl", "usernames"}:
            raise ValueError(
                f"do_ingest_profiles_dump: unknown fmt={fmt!r} "
                "(expected 'auto', 'jsonl', or 'usernames')"
            )
        if rate_per_second < 0:
            raise ValueError(
                "do_ingest_profiles_dump: rate_per_second must be >= 0, "
                f"got {rate_per_second}"
            )
        if limit is not None and limit < 1:
            raise ValueError(
                f"do_ingest_profiles_dump: limit must be >= 1, got {limit}"
            )

        stats = {"rows_seen": 0, "processed": 0, "skipped": 0, "errors": 0}

        if fmt == "jsonl":
            iterator = _iter_jsonl_rows(filepath, offset)
        else:
            iterator = _iter_username_rows(filepath, offset)

        pace_rows = fmt != "jsonl" and rate_per_second > 0
        last_row_started_at: float | None = None
        for line_no, row in iterator:
            if limit is not None and stats["rows_seen"] >= limit:
                break
            if pace_rows:
                last_row_started_at = _pace_ingest_rows(
                    last_row_started_at=last_row_started_at,
                    rate_per_second=rate_per_second,
                )
            stats["rows_seen"] += 1
            try:
                if fmt == "jsonl":
                    payload = APIResponse.model_validate(row)
                    user_id = do_user_created(
                        source,
                        oauth_id=payload.data[0].sub if payload.data else None,
                        kc_username=(
                            payload.data[0].profile.username if payload.data else None
                        ),
                        remote_data=payload,
                        send_status_callback=False,
                        run_synchronously=True,
                    )
                else:
                    user_id = do_user_created(
                        source,
                        kc_username=row,
                        resolve_sub_from_username=True,
                        update_existing=False,
                        send_status_callback=False,
                        run_synchronously=True,
                    )
            except Exception:  # noqa: BLE001 - logged, never propagated
                stats["errors"] += 1
                app.logger.exception(
                    "do_ingest_profiles_dump: line %d failed; continuing",
                    line_no,
                )
                continue
            if user_id is None:
                stats["skipped"] += 1
            else:
                stats["processed"] += 1

        app.logger.info(
            "do_ingest_profiles_dump: finished %s; rows_seen=%d processed=%d "
            "skipped=%d errors=%d",
            filepath,
            stats["rows_seen"],
            stats["processed"],
            stats["skipped"],
            stats["errors"],
        )
        return stats


@shared_task(ignore_result=False)
def do_backfill_cited_from_records(
    *,
    limit: int | None = None,
    dry_run: bool = False,
) -> dict[str, int]:
    """Walk all published RDM records and upsert a Names record for each ORCID.

    Thin Celery wrapper around
    `NamesSyncService.backfill_cited_orcid_from_records` (in
    `...services.names_sync`). Run once per deployment to backfill
    pre-component published records; the on-draft-save component
    handles new drafts going forward. Safe to re-run.

    Args:
        limit: Maximum number of records to scan; `None` walks the
            entire published corpus.
        dry_run: When `True`, count payloads but skip every Names
            upsert. The returned `upserted` counter will be `0`.

    Returns:
        The stats dict produced by
        `NamesSyncService.backfill_cited_orcid_from_records`.
    """
    with app.app_context():
        return current_names_sync_service.backfill_cited_orcid_from_records(
            limit=limit, dry_run=dry_run
        )
