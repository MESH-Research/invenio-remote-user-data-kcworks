# -*- coding: utf-8 -*-
#
# This file is part of the invenio-remote-user-data package.
# Copyright (C) 2023, MESH Research.
#
# invenio-remote-user-data is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

from datetime import datetime
from flask import current_app, session  # after_this_request, request,
from flask_principal import identity_changed, Identity  # identity_loaded,
from flask_security import current_user
from invenio_accounts.models import UserIdentity  # Role,
from . import config
from .service import RemoteGroupDataService, RemoteUserDataService
from .tasks import do_user_data_update, do_group_data_update

# from .utils import logger


def on_identity_changed(_, identity: Identity) -> None:
    """Update user data from remote server when current user is
    changed.
    """
    # FIXME: Do we need this check now that we're using webhooks?
    with current_app.app_context():
        # FIXME: for some reason we're getting a detached User object
        # downstream in the login process unless we do this. This is a
        # hack.
        user_roles_fix = current_user.roles  # noqa

        current_app.logger.info(
            "invenio_remote_user_data.ext: identity_changed signal received "
            f"for user {identity.id}"
        )
        # if self._data_is_stale(identity.id) and not self.update_in_progress:
        my_user_identity = UserIdentity.query.filter_by(
            id_user=identity.id
        ).one_or_none()
        # will have a UserIdentity if the user has logged in via an IDP
        if my_user_identity is not None:
            my_idp = my_user_identity.method
            my_remote_id = my_user_identity.id

            # TODO: For the moment we're not tracking the last update
            # time because we're using logins and webhooks to trigger updates.
            #
            # timestamp = datetime.utcnow().isoformat()
            # session.setdefault("user-data-updated", {})[
            #     identity.id
            # ] = timestamp

            celery_result = do_user_data_update.delay(  # noqa
                identity.id, my_idp, my_remote_id
            )


class InvenioRemoteUserData(object):
    """Flask extension for Invenio-remote-user-data.

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
        app.extensions["invenio-remote-user-data"] = self
        with app.app_context():
            app.logger.info("invenio-remote-user-data initialized")

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
        identity_changed.connect(on_identity_changed, app)
