# -*- coding: utf-8 -*-
#
# This file is part of the invenio-remote-user-data package.
# Copyright (C) 2023, MESH Research.
#
# invenio-remote-user-data is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

from datetime import datetime
from flask import session  # after_this_request, request,
from flask_principal import identity_changed, Identity  # identity_loaded,
from invenio_accounts.models import UserIdentity  # Role,
from . import config
from .service import RemoteUserDataService
from .tasks import do_user_data_update
from .utils import logger


def on_identity_changed(_, identity: Identity) -> None:
    """Update user data from remote server when current user is
    changed.
    """
    # FIXME: Do we need this check now that we're using webhooks?
    logger.info(
        "%%%%% identity_changed signal received for " f"user {identity.id}"
    )
    # if self._data_is_stale(identity.id) and not self.update_in_progress:
    my_user_identity = UserIdentity.query.filter_by(
        id_user=identity.id
    ).one_or_none()
    # will have a UserIdentity if the user has logged in via an IDP
    if my_user_identity is not None:
        my_idp = my_user_identity.method
        my_remote_id = my_user_identity.id

        timestamp = datetime.utcnow().isoformat()
        session.setdefault("user-data-updated", {})[identity.id] = timestamp
        celery_result = do_user_data_update.delay(  # noqa
            identity.id, my_idp, my_remote_id
        )
        # self.logger.debug('celery_result_id: '
        #                   f'{celery_result.id}')


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

    def init_config(self, app) -> None:
        """Initialize configuration for the extention.

        Args:
            app (_type_): _description_
        """
        for k in dir(config):
            if k.startswith("REMOTE_USER_DATA_"):
                app.config.setdefault(k, getattr(config, k))

    def init_services(self, app):
        """Initialize services for the extension.

        Args:
            app (_type_): _description_
        """
        self.service = RemoteUserDataService(app, config=app.config)

    def init_listeners(self, app):
        """Initialize listeners for the extension.

        Args:
            app (_type_): _description_
        """
        identity_changed.connect(on_identity_changed, app)
