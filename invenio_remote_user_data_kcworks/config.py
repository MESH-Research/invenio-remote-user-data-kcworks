#
# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

from .permissions import (
    CustomCommunitiesPermissionPolicy,
    RemoteUserDataPermissionPolicy,
)

REMOTE_USER_DATA_API_TIMEOUT = 5

REMOTE_USER_DATA_API_ENDPOINTS = {
    "knowledgeCommons": {
        "users": {
            "remote_endpoint": ("https://hcommons-dev.org/wp-json/commons/v1/users/"),
            "remote_identifier": "id",
            "remote_method": "GET",
            "token_env_variable_label": "COMMONS_API_TOKEN",
        },
        "groups": {
            "remote_endpoint": ("https://hcommons-dev.org/wp-json/commons/v1/groups/"),
            "remote_identifier": "id",
            "remote_method": "GET",
            "token_env_variable_label": "COMMONS_API_TOKEN",
        },
        "entity_types": {
            "users": {"events": ["created", "updated", "deleted"]},
            "groups": {"events": ["created", "updated", "deleted"]},
        },
    }
}

REMOTE_USER_DATA_UPDATE_INTERVAL = 1  # minutes between login-time syncs

# Per-entity mutex for concurrent remote user/group update Celery tasks (Redis via invenio_cache).
# When disabled, update tasks run without waiting for a lock.
REMOTE_USER_DATA_UPDATE_LOCK_ENABLED = True
# TTL (seconds) for the Redis lock key; should exceed typical update duration.
REMOTE_USER_DATA_UPDATE_LOCK_TIMEOUT = 120
# Retries when acquire returns status "waiting" (another update in progress).
REMOTE_USER_DATA_UPDATE_LOCK_MAX_RETRIES = 10
# Progressive backoff between retries: initial_backoff + (attempt * backoff_step).
REMOTE_USER_DATA_UPDATE_LOCK_INITIAL_BACKOFF = 1.0
REMOTE_USER_DATA_UPDATE_LOCK_BACKOFF_STEP = 1.0

COMMUNITIES_PERMISSION_POLICY = CustomCommunitiesPermissionPolicy

REMOTE_USER_DATA_PERMISSION_POLICY = RemoteUserDataPermissionPolicy

IDMS_TOKEN_UPDATE_TIMEOUT = 5

# SSO Broker Authentication
# -------------------------
SSO_BROKER_LOGIN_URL = None
SSO_BROKER_SILENT_LOGIN_URL = None
SSO_BROKER_VERIFY_NONCE_URL = None
SSO_BROKER_RETRY_COOKIE_NAME = "_sso_checked"
SSO_BROKER_COOKIE_TTL = 300  # 5 minutes in seconds
SSO_BROKER_SILENT_LOGIN_TIMEOUT = 3

REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_FAILURE = (
    "<p>Sorry, we "
    "couldn't log you into KCWorks.</p>"
    "<p>This is a problem on our end, so please try "
    "again later.</p>"
    "<p>In the meantime you can still browse and search open access "
    "works and collections as a guest.</p>"
    '<p class=" ui info message">Error message: {message}</p>'
)

REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_TIMEOUT = (
    "<p>Sorry, we "
    "couldn't log you into KCWorks.</p>"
    "<p>The KCProfiles app "
    "wasn't available to retrieve "
    "your member information. "
    "This is a problem on our end, so please try again later.</p>"
    "<p>In the meantime you can still browse and search open access "
    "works and collections as a guest.</p>"
    '<p class=" ui info message">Error message: {message}</p>'
)

REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_CONNECTION = (
    "<p>Sorry, we "
    "couldn't log you into KCWorks.</p>"
    "<p>There were problems communicating with the KCProfiles app to retrieve "
    "your member information. This is a problem on our end, so please "
    "try again later.</p>"
    "<p>In the meantime you can still browse and search open access "
    "works and collections as a guest.</p>"
    '<p class=" ui info message">Error message: {message}</p>'
)

REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_INVALID_STATE = (
    "<p>Sorry, we "
    "couldn't log you into KCWorks.</p>"
    "<p>There were problems validating the response from the "
    "authentication provider. Please try logging in again later.</p>"
    "<p>In the meantime you can still browse and search open access "
    "works and collections as a guest.</p>"
    '<p class=" ui info message">Error message: {message}</p>'
)

REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_INVALID_TOKEN = (
    REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_INVALID_STATE
)
