#
# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

from enum import StrEnum

from kombu import Exchange

from .permissions import (
    CustomCommunitiesPermissionPolicy,
    RemoteUserDataPermissionPolicy,
)


class UserDataStatus(StrEnum):
    """Outcome values for the Profiles works/status callback.

    Sent in the `status` field of POSTs to
    `/api/v1/members/{member_name}/works/status`.

    IMPORTANT: changing a member's value is a wire-protocol change and
    must be coordinated with the Profiles side.
    """

    PROCESSED = "PROCESSED"
    FAILED = "FAILED"


class KCNamesTag(StrEnum):
    """Discriminator tags applied to KCWorks-managed Names records.

    The Names vocabulary is shared with bulk-loaded data and other
    sources, so we tag every record we write to be able to tell ours
    apart at lookup, merge, and dedupe time. The two values below are
    the only tags `NamesSyncService` writes; tag-based filtering
    elsewhere in the codebase should reference these members rather
    than the bare strings.

    Members:
        USER: A Names record that mirrors a local KCWorks user.
        CITED: A Names record inserted from ORCID on first reference
            (e.g. an ORCID-identified contributor cited in a draft, or
            picked from the deposit form's ORCID proxy) for a person
            who is not (yet) a KCWorks user.

    The string values are persisted on Names records in OpenSearch and
    in the database, so changing them is a data-migration concern.
    """

    USER = "kcworks-user"
    CITED = "kcworks-cited"


class UserDataEvent(StrEnum):
    """Event values for the Profiles works/status callback.

    Sent in the `event` field of POSTs to
    `/api/v1/members/{member_name}/works/status`. Mirrors the
    `event` property carried by each entry in the inbound
    `updates.users` webhook payload, so the Profiles side can
    correlate the status callback with the original signal it sent.

    Only the two values KCWorks itself can report on are modelled
    here; `deleted` is intentionally absent because KCWorks does
    not act on `users.deleted` webhook events (see the API
    documentation for the rationale) and therefore never sends a
    status callback for one. The webhook view continues to accept
    `deleted` as a valid wire-format string.

    IMPORTANT: changing these values is a wire-protocol change and
    must be coordinated with the Profiles side.
    """

    CREATED = "created"
    UPDATED = "updated"


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

# Long-delay reschedule for the `do_user_created` and
# `do_user_data_update` tasks after Celery's retries
# fail.
REMOTE_USER_DATA_USER_CREATED_RESCHEDULE_DELAY = 3600

REMOTE_USER_DATA_MQ_EXCHANGE = Exchange(
    "user-data-updates",
    type="direct",
    delivery_mode="transient",  # in-memory queue
)

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
