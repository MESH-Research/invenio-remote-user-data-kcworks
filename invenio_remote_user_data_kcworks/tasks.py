# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Celery task to update user data from remote API."""

import contextlib
import json
from datetime import UTC, datetime, timedelta

import requests
from celery import shared_task
from celery.exceptions import MaxRetriesExceededError
from flask import current_app as app
from invenio_access.permissions import system_identity
from invenio_accounts.errors import AlreadyLinkedError
from invenio_accounts.models import User, UserIdentity
from invenio_accounts.proxies import current_datastore as datastore
from invenio_db import db
from sqlalchemy.exc import IntegrityError

from .client import UserDataAPIClient
from .config import UserDataEvent, UserDataStatus
from .errors import LocalUserNotFoundError, NoIDPFoundError, UserCreationFailed
from .proxies import (
    current_names_sync_service,
    current_remote_group_service,
    current_remote_user_data_service,
)
from .types.auth import AccountInfo
from .types.profiles_api import APIResponse
from .utils.auth import CILogonHelpers, UserIdentifierHelpers


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
    sub: str | None,
    status: UserDataStatus,
    event: UserDataEvent,
    *,
    user: User | None = None,
    method: str | None = None,
    retry_at: str | None = None,
    note: str | None = None,
) -> None:
    """Best-effort wrapper around the Profiles status callback.

    Resolves the KC member name from `user` (preferred) or from
    `UserIdentity(method, id=sub)` and forwards the call to
    `UserDataAPIClient.send_user_status_callback()`, which
    constructs the URL as
    `/api/v1/members/{username or "unknown"}/works/status` and
    sends both the resolved `username` (possibly `null`) and the
    raw `sub` in the body.

    The callback is skipped only when `sub` is also missing (no
    addressee at all is meaningful for the Profiles side). Otherwise
    even an unresolvable sub gets a callback under the `unknown`
    member-name slot so the Profiles operator at least sees the
    failure.

    Args:
        sub: The OAuth `sub` from the webhook
            (`UserIdentity.id`), or `None`.
        status: `UserDataStatus` member.
            `UserDataStatus.PROCESSED` or `UserDataStatus.FAILED`.
        event: `UserDataEvent` member, mirroring the inbound webhook
            `event` field.
        user: Optional local `User` to read the member name from
            without an extra `UserIdentity` lookup.
        method: Optional `UserIdentity.method` to disambiguate the
            sub lookup when `user` is not supplied.
        retry_at: Optional ISO 8601 UTC timestamp when a follow-up
            attempt is already scheduled.
        note: Optional freeform diagnostic string.
    """
    if not sub:
        # No sub means the upstream side has nothing to correlate
        # against either; bail silently.
        return
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


def _handle_profiles_api_failure(
    self,
    exc: Exception,
    *,
    sub: str | None,
    event: UserDataEvent,
    method: str | None,
    kwargs: dict,
    reschedule_task,
    reschedule_args: tuple,
    send_status_callback: bool = True,
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

    Args:
        self: The bound Celery task instance (caller passes its own
            `self`). Used for `self.request.retries`,
            `self.retry`, `self.max_retries`, and `self.name`.
        exc: The HTTP exception that triggered this call.
        sub: The OAuth `sub` (`UserIdentity.id`) for the affected
            user, used for the status callback. May be `None`;
            `_send_status` will skip silently in that case.
        event: `UserDataEvent` member, mirroring the inbound webhook
            `event` field.
        method: The `UserIdentity.method` for resolving the sub
            into a KC member name (status-callback addressing).
        kwargs: The original `**kwargs` passed to the calling task,
            forwarded to `apply_async` on the long-delay reschedule
            so any caller-specified Celery options are preserved.
        reschedule_task: The Celery task object to re-enqueue
            (typically the calling task itself).
        reschedule_args: Positional `args` tuple to pass to
            `reschedule_task.apply_async` on the long-delay
            reschedule path.
    """
    retries = self.request.retries or 0
    countdown = min(30 * (2**retries), 600)
    try:
        if send_status_callback:
            _send_status(
                sub,
                UserDataStatus.FAILED,
                event,
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
                sub,
                UserDataStatus.FAILED,
                event,
                method=method,
                retry_at=_retry_at_iso(long_delay),
                note=(
                    f"profiles_api:{type(exc).__name__}:retries_exhausted_rescheduled"
                ),
            )
        reschedule_task.apply_async(
            args=reschedule_args,
            kwargs=kwargs,
            countdown=long_delay,
        )


@shared_task(
    bind=True,
    ignore_result=False,
    max_retries=5,
)
def do_user_data_update(
    self,
    user_id: int,
    idp: str | None = None,
    remote_id: str | None = None,
    send_status_callback: bool = True,
    **kwargs,
) -> tuple[User, dict, list[str], dict] | None:
    """Perform a user metadata update.

    On every resolution path this task sends a PROCESSED/FAILED
    callback response to the Profiles
    `/api/v1/members/{member_name}/works/status` endpoint. The
    KC member name needed for the callback URL and body is resolved
    locally. When no member name can be resolved the callback still
    fires with `unknown` in place of the member username in the URL,
    so that the Profiles operator can correlate by `sub` in the
    response body.

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
    config key). Status callbacks include a `retry_at` timestamp so
    the Profiles operator can see another attempt is pending.

    Other unexpected exceptions trigger a FAILED callback and are
    re-raised so Celery surfaces the error.

    Args:
        self: The bound Celery task instance, used by
            `_handle_profiles_api_failure()` for `self.retry`.
        user_id: The local ID of the user to update.
        idp: The remote service configuration to use for the update.
        remote_id: The ID of the user on the remote system (the
            OAuth `sub`, also stored as `UserIdentity.id`).
        send_status_callback: A boolean flag to control whether a status
            callback is sent to the remote API endpoint on task failure/completion.
            Defaults to True.
        **kwargs: Reserved for future Celery options; forwarded
            unchanged to the long-delay reschedule path.

    Returns:
        A four-tuple (indices 0–3):

        0. The updated `User` object.
        1. A dictionary of the updated user data (including only the changed
           keys and values).
        2. A list of the updated user's group memberships.
        3. A dictionary of the changes to the user's group memberships (with
           the keys `added_groups`, `dropped_groups`, and
           `unchanged_groups`).

        `None` when the task has been re-enqueued for a long-delay
        retry after exhausting its bounded retry budget.

    Raises:
        LocalUserNotFoundError: When the local Invenio user id does not exist.
        NoIDPFoundError: When `idp` cannot be inferred from a
            `UserIdentity` for `user_id`.
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

        if not idp:
            user = datastore.get_user_by_id(user_id)
            if send_status_callback:
                _send_status(
                    remote_id,
                    UserDataStatus.FAILED,
                    UserDataEvent.UPDATED,
                    user=user,
                    note="NoIDPFoundError",
                )
            raise NoIDPFoundError(f"No IDP found for user {user_id}")

        service = current_remote_user_data_service
        try:
            user, updated_data, groups, groups_changes = (
                service.update_user_from_remote(
                    system_identity, user_id, idp, remote_id
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
                sub=remote_id,
                event=UserDataEvent.UPDATED,
                method=idp,
                kwargs=kwargs,
                reschedule_task=do_user_data_update,
                reschedule_args=(user_id, idp, remote_id),
                send_status_callback=send_status_callback,
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
                    remote_id,
                    UserDataStatus.FAILED,
                    UserDataEvent.UPDATED,
                    user=user,
                    method=idp,
                    note="LocalUserNotFoundError",
                )
            raise
        except Exception as exc:
            user = datastore.get_user_by_id(user_id)
            if send_status_callback:
                _send_status(
                    remote_id,
                    UserDataStatus.FAILED,
                    UserDataEvent.UPDATED,
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
                remote_id,
                UserDataStatus.PROCESSED,
                UserDataEvent.UPDATED,
                user=user,
                method=idp,
            )
        return user, updated_data, groups, groups_changes


@shared_task(ignore_result=False)
def do_group_data_update(idp, remote_id, **kwargs):
    """Perform a group metadata update."""

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
    """Find possible duplicate entries in the Names vocabulary."""
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
def do_user_created(
    self,
    idp: str,
    oauth_id: str,
    *,
    remote_data: APIResponse | None = None,
    **kwargs,
) -> int | None:
    """Provision a local KCWorks user from a remote `created` webhook event.

    Triggered from
    `invenio_remote_user_data_kcworks.services.service.RemoteUserDataService`
    when a `users.created` webhook event is consumed from the
    `user-data-updates` queue. The remote profile is fetched from the
    Profiles API by the OAuth `sub` (`oauth_id` — also the value
    stored as `UserIdentity.id`), the local `User` is created
    (or matched if it already exists by external id, ORCID, KC
    username, or email), the `UserIdentity` link is ensured
    (idempotent), and finally the standard update path is invoked to
    populate `user_profile` fields and group memberships.

    The task is idempotent: if a `UserIdentity` already exists for the
    given `(idp, oauth_id)` pair the task delegates to
    `do_user_data_update()` and returns the existing user id.

    Failure handling
    ----------------

    Transient HTTP failures while talking to the Profiles API
    (`requests.RequestException` / `requests.Timeout`) -- whether
    they occur during the initial profile fetch or during the
    follow-up `update_user_from_remote` call -- are routed through
    the shared `_handle_profiles_api_failure()` helper. That
    helper applies bounded exponential backoff (30s, 60s, 120s, …,
    capped at 600s) for up to `max_retries` attempts; on exhaustion
    it logs an error and re-enqueues the task with a long countdown
    (`REMOTE_USER_DATA_USER_CREATED_RESCHEDULE_DELAY`, default 1
    hour, shared with `do_user_data_update`) so provisioning will
    eventually succeed once the Profiles service recovers.

    Status callback
    ---------------

    On every resolution path (success, give-up after no profile data,
    give-up after user could not be matched/created, scheduled retry,
    or scheduled long-delay reschedule) this task sends a
    PROCESSED/FAILED callback response body to the Profiles
    `/api/v1/members/{member_name}/works/status` endpoint. When a
    follow-up attempt is already queued (a Celery retry or the
    long-delay reschedule) the callback body includes a `retry_at`
    timestamp so the Profiles side can avoid prompting an operator
    while the next attempt is still pending.

    Args:
        self: The bound Celery task instance, used to drive
            `self.retry` for transient Profiles API failures.
        idp: The identity provider name (matches a key in
            `REMOTE_USER_DATA_API_ENDPOINTS`). For Knowledge Commons this
            is `"knowledgeCommons"`.
        oauth_id: The external subject identifier (`sub`) for the
            user on the remote IDP.
        remote_data: Optional pre-fetched Profiles API response for
            `oauth_id`. When provided, skips the initial Profiles API
            fetch and uses the supplied payload for both user creation
            and the downstream `update_user_from_remote` call. Used by
            the bulk JSONL ingest path
            (`do_ingest_profiles_dump`) so we can replay an offline
            Profiles dump without re-hitting the live API. The
            delegating-to-`do_user_data_update` short-circuit (when a
            local `UserIdentity` already exists) ignores this argument.
        **kwargs: Reserved for future Celery options; currently ignored.

    Raises:
        LocalUserNotFoundError: If the local user row is missing during
            ``update_user_from_remote`` (after FAILED status callback).

    Returns:
        The id of the matched/created local user, `None` when no
        remote profile data was returned, or `None` when the
        Profiles API was unreachable and the task has been rescheduled
        for a future attempt.
    """
    with app.app_context():
        if not oauth_id:
            app.logger.warning("do_user_created: missing oauth_id; skipping")
            # _send_status will skip silently when sub is empty.
            _send_status(
                None,
                UserDataStatus.FAILED,
                UserDataEvent.CREATED,
                note="missing_oauth_id",
            )
            return None

        auth_method = idp
        if idp == "knowledgeCommons":
            kc_idps = app.config.get("KC_REMOTE_IDPS") or []
            if kc_idps:
                auth_method = kc_idps[0]

        existing = UserIdentity.query.filter_by(
            id=oauth_id, method=auth_method
        ).one_or_none()
        if existing is not None:
            app.logger.debug(
                "do_user_created: UserIdentity already exists for "
                f"sub={oauth_id} method={auth_method}; delegating to "
                "do_user_data_update"
            )
            # Delegated path: do_user_data_update will fire its own
            # PROCESSED/FAILED callback once it resolves, so we don't
            # send one from here.
            do_user_data_update.delay(existing.id_user, idp, oauth_id)
            return existing.id_user

        if remote_data is not None:
            profile_response = remote_data
        else:
            try:
                profile_response = UserDataAPIClient.fetch_user_profile(sub_id=oauth_id)
            except (requests.RequestException, requests.Timeout) as exc:
                app.logger.warning(
                    f"do_user_created: failed to fetch profile for "
                    f"sub={oauth_id}: {exc!r}"
                )
                _handle_profiles_api_failure(
                    self,
                    exc,
                    sub=oauth_id,
                    event=UserDataEvent.CREATED,
                    method=auth_method,
                    kwargs=kwargs,
                    reschedule_task=do_user_created,
                    reschedule_args=(idp, oauth_id),
                )
                # Only reached on the long-delay reschedule branch.
                return None

        if not profile_response or not getattr(profile_response, "data", None):
            app.logger.info(
                f"do_user_created: no profile data returned for "
                f"sub={oauth_id}; skipping user creation"
            )
            _send_status(
                oauth_id,
                UserDataStatus.FAILED,
                UserDataEvent.CREATED,
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
                    _send_status(
                        oauth_id,
                        UserDataStatus.FAILED,
                        UserDataEvent.CREATED,
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
                _send_status(
                    oauth_id,
                    UserDataStatus.FAILED,
                    UserDataEvent.CREATED,
                    method=auth_method,
                    note="user_creation_failed",
                )
                return None

        if user is None:
            app.logger.warning(
                f"do_user_created: could not find or create user for sub={oauth_id}"
            )
            _send_status(
                oauth_id,
                UserDataStatus.FAILED,
                UserDataEvent.CREATED,
                method=auth_method,
                note="user_match_or_create_failed",
            )
            return None

        with contextlib.suppress(AlreadyLinkedError):
            CILogonHelpers.link_user_to_oauth_identifier(user, auth_method, oauth_id)

        # Run the normal update path so user_profile fields and group
        # memberships are populated from the same payload we already
        # fetched. HTTP failures here get the same retry+reschedule
        # treatment. A re-run of this task will short-circuit through
        # the existing-identity branch and run `do_user_data_update`.
        try:
            current_remote_user_data_service.update_user_from_remote(
                system_identity,
                user.id,
                "knowledgeCommons" if idp == "knowledgeCommons" else idp,
                oauth_id,
                remote_data=profile_response,
            )
        except (requests.RequestException, requests.Timeout) as exc:
            app.logger.warning(
                "do_user_created: Profiles API failure during "
                "update_user_from_remote for sub=%s: %r",
                oauth_id,
                exc,
            )
            _handle_profiles_api_failure(
                self,
                exc,
                sub=oauth_id,
                event=UserDataEvent.CREATED,
                method=auth_method,
                kwargs=kwargs,
                reschedule_task=do_user_created,
                reschedule_args=(idp, oauth_id),
            )
            # Only reached on the long-delay reschedule branch.
            return user.id
        except LocalUserNotFoundError as exc:
            app.logger.error(
                "do_user_created: local user missing during update_user_from_remote "
                "(%s); user_id=%s sub=%s idp=%s",
                exc,
                user.id,
                oauth_id,
                idp,
            )
            _send_status(
                oauth_id,
                UserDataStatus.FAILED,
                UserDataEvent.CREATED,
                user=user,
                method=auth_method,
                note="LocalUserNotFoundError",
            )
            raise
        except Exception as exc:
            _send_status(
                oauth_id,
                UserDataStatus.FAILED,
                UserDataEvent.CREATED,
                user=user,
                method=auth_method,
                note=f"update_user_from_remote:{type(exc).__name__}",
            )
            raise

        sync_user_to_names.delay(user.id)

        _send_status(
            oauth_id,
            UserDataStatus.PROCESSED,
            UserDataEvent.CREATED,
            user=user,
            method=auth_method,
        )
        return user.id


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
    and check whether it starts with ``{``. Anything else is assumed to be a
    plain-text username list (one username per line; CSV header optional).

    Args:
        filepath: Path to the file to inspect.

    Returns:
        Either ``"jsonl"`` or ``"usernames"``.
    """
    with open(filepath, encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            return "jsonl" if stripped.startswith("{") else "usernames"
    return "usernames"


def _iter_jsonl_rows(filepath: str):
    """Yield parsed JSON objects from a JSONL file, skipping blank lines."""
    with open(filepath, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            yield json.loads(line)


def _iter_username_rows(filepath: str):
    """Yield trimmed usernames from a one-column file, skipping blanks and comments."""
    with open(filepath, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # Tolerate a CSV-style header row labelled "username" (case-insensitive).
            if line.lower() in {"username", '"username"'}:
                continue
            # If somebody hands us a CSV with extra columns, take the first one.
            yield line.split(",", 1)[0].strip().strip('"')


@shared_task(ignore_result=False)
def do_ingest_profiles_dump(
    filepath: str,
    *,
    fmt: str = "auto",
    source: str = "knowledgeCommons",
) -> dict[str, int]:
    """Bulk-create / update local users from a Profiles dump file.

    Two input shapes are accepted; the format is sniffed by default
    from the first non-blank line:

    - **JSONL** (`fmt="jsonl"`): each line is one Profiles API response
      payload (matching `APIResponse` from `...types.profiles_api`). For
      every row we call `do_user_created` *synchronously* with
      `remote_data=<row>` so no live Profiles API I/O is performed.
    - **Usernames** (`fmt="usernames"`): one KC username per line (CSV
      header `username` and `#` comment lines tolerated). For every row
      we call `do_user_created` *synchronously* without pre-fetched
      data, so the live Profiles API is hit per row exactly as a
      webhook `users.created` event would. The downstream lazy-
      provisioning logic (the `UserIdentity`-exists short-circuit
      delegating to `do_user_data_update`) gives "create or update"
      semantics for both new and known usernames.

    Both code paths run synchronously *inside this single task* so a
    long ingest is observable as one Celery entry rather than thousands
    of per-row tasks; this is friendlier to Profiles API rate limits and
    easier for operators to monitor / abort.

    The operation is idempotent provided Profiles API-served data does not
    change between runs. Already-existing KCWorks users simply have their
    metadata updated from the Profiles API.

    Args:
        filepath: Absolute path to the dump file. Read with UTF-8.
        fmt: `"auto"` (sniff), `"jsonl"`, or `"usernames"`.
        source: The IDP key to pass to `do_user_created`. Defaults to
            `"knowledgeCommons"`.

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
            `"usernames"`.
    """
    with app.app_context():
        if fmt == "auto":
            fmt = _sniff_dump_format(filepath)
        if fmt not in {"jsonl", "usernames"}:
            raise ValueError(
                f"do_ingest_profiles_dump: unknown fmt={fmt!r} "
                "(expected 'auto', 'jsonl', or 'usernames')"
            )

        stats = {"rows_seen": 0, "processed": 0, "skipped": 0, "errors": 0}

        if fmt == "jsonl":
            iterator = _iter_jsonl_rows(filepath)
        else:
            iterator = _iter_username_rows(filepath)

        for row in iterator:
            stats["rows_seen"] += 1
            try:
                if fmt == "jsonl":
                    payload = APIResponse.model_validate(row)
                    if not payload.data:
                        stats["skipped"] += 1
                        continue
                    oauth_id = payload.data[0].sub
                    user_id = do_user_created(source, oauth_id, remote_data=payload)
                else:
                    user_id = do_user_created(source, row)
            except Exception:  # noqa: BLE001 - logged, never propagated
                stats["errors"] += 1
                app.logger.exception(
                    "do_ingest_profiles_dump: row %d failed; continuing",
                    stats["rows_seen"],
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
