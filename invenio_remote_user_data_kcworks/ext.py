# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Main extension class for invenio-remote-user-data-kcworks."""

import re

import arrow
from flask import Response, current_app, request, session
from flask_login import current_user, user_logged_in, user_logged_out
from invenio_accounts.models import User

from . import config
from .proxies import current_remote_user_data_service
from .services.service import RemoteGroupDataService, RemoteUserDataService
from .tasks import do_user_data_update
from .utils import BrokerHelpers
from .views import sso_broker_login


def on_user_logged_out(_, user: User) -> None:
    """Send global logout signal to profiles API when user logs out."""
    kc_username = user.user_profile.get("identifier_kc_username")
    if not kc_username:
        kc_username = re.sub("knowledgeCommons", "", user.username, flags=re.IGNORECASE)
    current_remote_user_data_service.log_user_out_global(kc_username)


def on_user_logged_in(_, user: User) -> None:
    """Update user data from remote server when current user is changed."""
    with current_app.app_context():
        if user.id:
            last_timestamp = session.get("user-data-updated", {}).get(user.id)
            last_updated = arrow.get(last_timestamp) if last_timestamp else None
            update_interval = current_app.config.get(
                "INVENIO_REMOTE_USER_DATA_UPDATE_INTERVAL", 10
            )

            if not last_updated or last_updated < arrow.now("UTC").shift(
                minutes=-1 * update_interval
            ):
                new_timestamp = arrow.now("UTC").isoformat()
                session.setdefault("user-data-updated", {})[user.id] = new_timestamp

                do_user_data_update.delay(user.id)  # noqa


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
        self.service = RemoteUserDataService(app, config=app.config)
        self.group_service = RemoteGroupDataService(app, config=app.config)

    def init_listeners(self, app):
        """Initialize listeners for the extension.

        Args:
            app (_type_): _description_
        """
        user_logged_in.connect(on_user_logged_in, app)
        user_logged_out.connect(on_user_logged_out, app)

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

            app.logger.debug("CHECKING FOR SSO LOGIN")
            cu = current_user._get_current_object()
            app.logger.debug(f"is_anonymous? {cu.is_anonymous}")
            if not getattr(cu, "is_anonymous", False):
                return

            if BrokerHelpers.ready_for_login_broker_check():
                app.logger.debug("ready_for_login_broker_check")
                try:
                    # NOTE: This must return the redirect response to the browser.
                    # If we don't return it, the redirect is constructed but never sent
                    # to the client, so the broker callback won't be hit.
                    return sso_broker_login(next=request.url, silent=True)

                except Exception:
                    current_app.logger.exception(
                        "Silent SSO login check failed unexpectedly"
                    )
