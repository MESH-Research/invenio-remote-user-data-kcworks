# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Session-backed throttle for login-time remote user-data sync."""

import arrow
from flask import session

SESSION_USER_DATA_UPDATED_KEY = "user-data-updated"


def record_login_sync_timestamp(user_id: int) -> None:
    """Mark that a login-time sync ran or was enqueued for ``user_id``.

    Stored in the per-browser Flask session so ``on_user_logged_in`` can skip
    a duplicate ``do_user_data_update`` enqueue (e.g. after broker inline sync).
    """
    session.setdefault(SESSION_USER_DATA_UPDATED_KEY, {})[user_id] = (
        arrow.now("UTC").isoformat()
    )


def login_sync_is_due(user_id: int, interval_seconds: int) -> bool:
    """Return whether login should enqueue a remote user-data update.

    Args:
        user_id: Local Invenio user id.
        interval_seconds: Minimum seconds since the last session-recorded sync.

    Returns:
        True when no timestamp exists or the interval has elapsed.
    """
    last_timestamp = session.get(SESSION_USER_DATA_UPDATED_KEY, {}).get(user_id)
    if not last_timestamp:
        return True
    last_updated = arrow.get(last_timestamp)
    return last_updated < arrow.now("UTC").shift(seconds=-interval_seconds)
