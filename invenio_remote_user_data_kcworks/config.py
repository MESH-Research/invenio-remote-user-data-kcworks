# -*- coding: utf-8 -*-
#
# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

from kombu import Exchange

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

REMOTE_USER_DATA_UPDATE_INTERVAL = 1  # 1 hour

REMOTE_USER_DATA_MQ_EXCHANGE = Exchange(
    "user-data-updates",
    type="direct",
    delivery_mode="transient",  # in-memory queue
)

COMMUNITIES_PERMISSION_POLICY = CustomCommunitiesPermissionPolicy

REMOTE_USER_DATA_PERMISSION_POLICY = RemoteUserDataPermissionPolicy

IDMS_TOKEN_UPDATE_TIMEOUT = 5

IDMS_CILOGON_PUBLIC_KEY_TIMEOUT = 30

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
