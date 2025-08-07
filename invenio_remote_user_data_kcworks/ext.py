# -*- coding: utf-8 -*-
#
# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

import arrow
from flask import current_app, session  # after_this_request, request,
from flask_login import user_logged_in

# from flask_principal import  identity_changed, Identity
from flask_security import current_user
from invenio_accounts.models import User

from . import config
from .service import RemoteGroupDataService, RemoteUserDataService
from .tasks import do_user_data_update


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
            last_updated = (
                arrow.get(last_timestamp) if last_timestamp else None
            )
            update_interval = current_app.config.get(
                "INVENIO_REMOTE_USER_DATA_UPDATE_INTERVAL", 10
            )

            if not last_updated or last_updated < arrow.now("UTC").shift(
                minutes=-1 * update_interval
            ):
                new_timestamp = arrow.now("UTC").isoformat()
                session.setdefault("user-data-updated", {})[
                    user.id
                ] = new_timestamp

                do_user_data_update.delay(user.id)  # noqa


class InvenioRemoteUserData(object):
    """Flask extension for Invenio-remote-user-data-kcworks.

    Args:
        object (_type_): _description_
    """

    def __init__(self, app=None) -> None:
        """Extention initialization."""
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
