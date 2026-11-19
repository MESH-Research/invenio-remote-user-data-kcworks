# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Main extension class for invenio-remote-user-data-kcworks."""

import os
import re

from flask import Response, current_app, request
from flask_login import current_user, user_logged_in, user_logged_out
from invenio_accounts.models import User
from invenio_db import db
from kcworks.services.networks.resolver_service import (
    ensure_sso_before_network_resolver,
)

from . import config
from .filters.user_profile_dict import user_profile_dict
from .proxies import current_remote_user_data_service
from .roles import ensure_service_capabilities
from .services.config import RemoteGroupDataServiceConfig, RemoteUserDataServiceConfig
from .services.names_sync import NamesSyncService
from .services.record_creatibutor_sync import RecordCreatibutorSyncService
from .services.service import RemoteGroupDataService, RemoteUserDataService
from .tasks import do_user_data_update
from .utils.broker import BrokerHelpers
from .utils.login_sync import login_sync_is_due, record_login_sync_timestamp
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
        if user.id:
            update_interval = current_app.config["REMOTE_USER_DATA_UPDATE_INTERVAL"]
            if login_sync_is_due(user.id, update_interval):
                record_login_sync_timestamp(user.id)
                do_user_data_update.delay(user.id, send_status_callback=False)  # noqa
                # Eager Celery nests the update on the shared test connection;
                # release this context's savepoint before teardown rolls it back.
                db.session.commit()


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
        self.init_template_filters(app)
        self.init_middleware(app)
        app.extensions["invenio-remote-user-data-kcworks"] = self

    def init_template_filters(self, app) -> None:
        """Register Jinja template filters owned by this extension."""
        app.add_template_filter(user_profile_dict)

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
        self.record_creatibutor_sync_service = RecordCreatibutorSyncService(
            app, config=app.config
        )

    def init_listeners(self, app):
        """Initialize listeners for the extension.

        Args:
            app (_type_): _description_
        """
        user_logged_in.connect(on_user_logged_in, app)
        user_logged_out.connect(on_user_logged_out, app)

    def init_middleware(self, app):
        """Initialize before_request handlers on the Flask app."""

        funcs = app.before_request_funcs.get(None, [])
        prepend_funcs = [sso_silent_login_check]
        app.before_request_funcs[None] = prepend_funcs + funcs
        ensure_sso_before_network_resolver(app)


def _register_kcworks_names_schema_override(app) -> None:
    """Point `names/name-v1.0.0.json` at this package's relaxed schema file.

    Called from `finalize_app` / `api_finalize_app` below, which Invenio runs
    because they are registered via the `invenio_base.finalize_app` and
    `invenio_base.api_finalize_app` *entry point groups* in `pyproject.toml`
    (not via `invenio_jsonschemas.schemas` — we do not register schema dirs
    that way here; that would duplicate the vocabulary path).

    At runtime we use `InvenioJSONSchemasState.register_schema` so this path
    wins over the copy bundled with `invenio-vocabularies`.
    """
    try:
        state = app.extensions["invenio-jsonschemas"]
    except KeyError:
        return
    root = os.path.join(os.path.dirname(__file__), "jsonschemas")
    state.register_schema(root, "names/name-v1.0.0.json")


def finalize_app(app) -> None:
    """UI finalize hook; registered on `invenio_base.finalize_app`.

    Ensures Profiles sync / SSO logout capability roles and service accounts.
    """
    _register_kcworks_names_schema_override(app)
    ensure_service_capabilities()


def api_finalize_app(app) -> None:
    """API finalize hook; registered on `invenio_base.api_finalize_app`.

    Ensures Profiles sync / SSO logout capability roles and service accounts.
    """
    _register_kcworks_names_schema_override(app)
    ensure_service_capabilities()
