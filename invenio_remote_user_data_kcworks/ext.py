# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Main extension class for invenio-remote-user-data-kcworks."""

import datetime
import os
import re

import arrow
from flask import Response, current_app, request
from flask_login import current_user, user_logged_in, user_logged_out
from invenio_accounts.models import User
from invenio_queues.proxies import current_queues

from . import config
from .proxies import current_remote_user_data_service
from .services.config import RemoteGroupDataServiceConfig, RemoteUserDataServiceConfig
from .services.names_sync import NamesSyncService
from .services.service import RemoteGroupDataService, RemoteUserDataService
from .signals import remote_data_updated
from .tasks import (
    do_group_data_update,
    do_user_created,
    do_user_data_update,
)
from .utils.broker import BrokerHelpers
from .views import sso_broker_login


def on_user_logged_out(_, user: User) -> None:
    """Send global logout signal to profiles API when user logs out."""
    kc_username = user.user_profile.get("identifier_kc_username")
    if not kc_username:
        kc_username = re.sub(
            "knowledgeCommons-", "", user.username, flags=re.IGNORECASE
        )
    current_remote_user_data_service.log_user_out_global(kc_username)


def on_user_logged_in(_, user: User) -> None:
    """Update user data from remote server when current user is changed."""
    with current_app.app_context():
        update_interval = current_app.config.get(
            "INVENIO_REMOTE_USER_DATA_UPDATE_INTERVAL", 30
        )
        if user.id and (
            arrow.utcnow() - arrow.get(user.updated)
            > datetime.timedelta(seconds=update_interval)
        ):
            do_user_data_update.delay(user.id, send_status_callback=False)  # noqa


def on_remote_data_updated(_, events: list) -> None:
    """Drain the user-data-updates queue and dispatch by entity type.

    Single consumer for the `remote_data_updated` signal: drains
    `current_queues.queues["user-data-updates"]` once per signal
    firing and routes each event to the appropriate Celery task
    based on `entity_type` + `event`.

    Replaces the per-service `__init__` handlers that previously
    each drained the same queue, racing each other and silently
    skipping events whose `entity_type` didn't match. Living in
    `ext.py` keeps signal-subscription wiring out of the service
    classes themselves.

    Unhandled event types (e.g. `groups` + `deleted`, which is
    not yet implemented) are logged at warning level and skipped so
    a single unrecognised event can't abort queue draining for the
    rest of the batch.

    Args:
        _: The Flask app sender (positional arg required by Blinker;
            unused).
        events: Forwarded by `RemoteUserDataUpdateWebhook` for
            logging/diagnostic context; the authoritative list of
            events to process is read from the queue itself.
    """
    for event in current_queues.queues["user-data-updates"].consume():
        entity_type = event.get("entity_type")
        evt = event.get("event")

        if entity_type == "users" and evt == "updated":
            do_user_data_update.delay(  # noqa
                event["user_id"], event["idp"], event["oauth_id"]
            )
        elif entity_type == "users" and evt == "created":
            # Lazy provisioning: the task is idempotent and will
            # short-circuit if the user already exists.
            do_user_created.delay(event["idp"], event["oauth_id"])  # noqa
        elif entity_type == "groups" and evt in ("created", "updated"):
            do_group_data_update.delay(event["idp"], event["id"])  # noqa
        else:
            current_app.logger.warning(
                "on_remote_data_updated: unhandled event "
                "(entity_type=%r, event=%r); skipping. Full event=%r",
                entity_type,
                evt,
                event,
            )


class InvenioRemoteUserData:
    """Flask extension for Invenio-remote-user-data-kcworks.

    Args:
        object (_type_): _description_
    """

    def __init__(self, app=None) -> None:
        """Extension initialization."""
        if app:
            self.init_app(app)

    def init_app(self, app) -> None:
        """Registers the Flask extension during app initialization.

        Args:
            app (Flask): the Flask application object on which to initialize
                the extension
        """
        self.init_config(app)
        self.init_services(app)
        self.init_listeners(app)
        app.extensions["invenio-remote-user-data-kcworks"] = self

    def init_config(self, app) -> None:
        """Initialize configuration for the extention.

        Args:
            app (_type_): _description_
        """
        for k in dir(config):
            if k.startswith(("REMOTE_USER_DATA_", "COMMUNITIES_", "SSO_BROKER_")):
                app.config.setdefault(k, getattr(config, k))

    def init_services(self, app):
        """Initialize services for the extension.

        Args:
            app (_type_): _description_
        """
        self.service = RemoteUserDataService(
            app, config=RemoteUserDataServiceConfig.build(app)
        )
        self.group_service = RemoteGroupDataService(
            app, config=RemoteGroupDataServiceConfig.build(app)
        )
        self.names_sync_service = NamesSyncService(app, config=app.config)

    def init_listeners(self, app):
        """Initialize listeners for the extension.

        Args:
            app (_type_): _description_
        """
        user_logged_in.connect(on_user_logged_in, app)
        user_logged_out.connect(on_user_logged_out, app)
        remote_data_updated.connect(on_remote_data_updated, app)

        @app.before_request
        def _sso_silent_login_check() -> Response | None:
            """Attempt transparent SSO login for anonymous users.

            If the user is anonymous and the TTL cookie has expired (or is
            absent), make a server-side request to the Profiles broker's
            silent-login endpoint. If an active session is found, decrypt
            the broker token, validate the nonce, and log the user in.

            Network errors or broker downtime are caught so they never
            block the original request.

            Returns:
                Response | None: If the user is anonymous and hasn't recently
                  checked for a Profiles login, returns a Flask redirect
                  response to send the user to the silent Profiles login check.
                  Otherwise, returns None.
            """
            # Silent SSO targets the UI app: skip REST API, static assets, broker
            # callback. Bare ``/api`` (no trailing slash) and ``SCRIPT_NAME=/api``
            # mounts are handled separately so we do not match e.g. ``/apiculture``.
            path = request.path or "/"
            script = (request.script_root or "").rstrip("/")
            if (
                path.startswith(("/api/", "/static/", "/sso/broker-callback/"))
                or path.rstrip("/") == "/api"
                or script == "/api"
                or path.rstrip("/").endswith("/sso/broker-callback")
            ):
                return

            cu = current_user._get_current_object()
            if not getattr(cu, "is_anonymous", False):
                return

            if BrokerHelpers.ready_for_login_broker_check():
                try:
                    # NOTE: This must return the redirect response to the browser.
                    # If we don't return it, the redirect is constructed but never sent
                    # to the browser, so the broker callback won't be hit.
                    return sso_broker_login(next=request.url, silent=True)

                except Exception:
                    current_app.logger.exception(
                        "Silent SSO login check failed unexpectedly"
                    )


def _register_kcworks_names_schema_override(app) -> None:
    """Point ``names/name-v1.0.0.json`` at this package's relaxed schema file.

    Called from ``finalize_app`` / ``api_finalize_app`` below, which Invenio runs
    because they are registered via the ``invenio_base.finalize_app`` and
    ``invenio_base.api_finalize_app`` *entry point groups* in ``pyproject.toml``
    (not via ``invenio_jsonschemas.schemas`` — we do not register schema dirs
    that way here; that would duplicate the vocabulary path).

    At runtime we use ``InvenioJSONSchemasState.register_schema`` so this path
    wins over the copy bundled with ``invenio-vocabularies``.
    """
    try:
        state = app.extensions["invenio-jsonschemas"]
    except KeyError:
        return
    root = os.path.join(os.path.dirname(__file__), "jsonschemas")
    state.register_schema(root, "names/name-v1.0.0.json")


def finalize_app(app) -> None:
    """UI finalize hook; registered on ``invenio_base.finalize_app``."""
    _register_kcworks_names_schema_override(app)


def api_finalize_app(app) -> None:
    """API finalize hook; registered on ``invenio_base.api_finalize_app``."""
    _register_kcworks_names_schema_override(app)
