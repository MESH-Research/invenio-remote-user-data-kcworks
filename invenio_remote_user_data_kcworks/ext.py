#
# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

import arrow
from flask import current_app, request, session
from flask_login import user_logged_in

# from flask_principal import  identity_changed, Identity
from invenio_accounts.models import User

from . import config
from .service import RemoteGroupDataService, RemoteUserDataService
from .tasks import do_user_data_update
from .views import (
    login,
    authorized,
    oauth_401_handler,
    oauth_403_handler,
    oauth_404_handler,
    oauth_500_handler,
)
from werkzeug.exceptions import (
    BadRequest,
    Forbidden,
    InternalServerError,
    MethodNotAllowed,
    NotFound,
    Unauthorized,
)


OAUTH_ROUTE_REWRITES = {
    "/oauth/login/<remote_app>/": login,
    "/oauth/authorized/<remote_app>/": authorized,
}


def on_user_logged_in(_, user: User) -> None:
    """Update user data from remote server when current user is
    changed.
    """
    # FIXME: Do we need this check now that we're using webhooks?
    # with current_app.app_context():

    with current_app.app_context():
        current_app.logger.info(
            "invenio_remote_user_data_kcworks.ext: user_logged_in "
            "signal received "
            f"for user {user.id}"
        )
        # current_app.logger.debug(f"current_user: {current_user}")
        # if self._data_is_stale(identity.id) and not self.update_in_progress:
        # my_user_identity = UserIdentity.query.filter_by(
        #     id_user=identity.id
        # ).one_or_none()
        # # will have a UserIdentity if the user has logged in via an IDP
        # if my_user_identity is not None:
        #     my_idp = my_user_identity.method
        #     my_remote_id = my_user_identity.id

        # TODO: For the moment we're not tracking the last update
        # time because we're using logins and webhooks to trigger updates.
        #
        if user.id:
            last_timestamp = session.get("user-data-updated", {}).get(user.id)
            current_app.logger.debug(f"last_updated: {last_timestamp}")
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
            if k.startswith("REMOTE_USER_DATA_"):
                app.config.setdefault(k, getattr(config, k))
            if k.startswith("COMMUNITIES_"):
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


def finalize_app(app):
    """Finalize app."""

    for rule in app.url_map.iter_rules():
        route_str = str(rule)

        if route_str in OAUTH_ROUTE_REWRITES:
            if rule.endpoint in app.view_functions:
                app.view_functions[rule.endpoint] = OAUTH_ROUTE_REWRITES[route_str]
            else:
                app.logger.debug(
                    f"Warning: Endpoint '{rule.endpoint}' not "
                    f"found for overwriting route '{route_str}'"
                )

    # Register error handlers on the Flask app for oauth blueprint routes
    # We can't register on the blueprint after it's been registered, so we
    # register on the app and check the blueprint name or URL path in the handler
    def oauth_error_wrapper(handler, blueprint_name="invenio_oauthclient"):
        """Wrap error handler to only handle errors from oauth blueprint."""
        def wrapped_handler(error):
            # Only handle errors from the oauth blueprint or oauth routes
            # Check if request context is available first
            try:
                # Check blueprint first, then URL path as fallback
                if (
                    (hasattr(request, "blueprint") and request.blueprint == blueprint_name)
                    or (hasattr(request, "path") and request.path.startswith("/oauth/"))
                ):
                    return handler(error)
            except RuntimeError:
                # Request context not available, let Flask handle it
                pass
            # Let Flask handle it with default behavior by returning None
            # This allows other error handlers to process the error
            return None
        return wrapped_handler

    # Register error handlers on the app (they'll check blueprint/URL internally)
    app.register_error_handler(Unauthorized, oauth_error_wrapper(oauth_401_handler))
    app.register_error_handler(NotFound, oauth_error_wrapper(oauth_404_handler))
    app.register_error_handler(Forbidden, oauth_error_wrapper(oauth_403_handler))
    app.register_error_handler(InternalServerError, oauth_error_wrapper(oauth_500_handler))
