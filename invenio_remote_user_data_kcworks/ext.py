# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Main extension class for invenio-remote-user-data-kcworks."""

import re
import time

import arrow
from flask import after_this_request, current_app, request, session, url_for
from flask_login import current_user, login_user, user_logged_in, user_logged_out
from invenio_accounts.models import User

from . import config
from .client import SessionBrokerAPIClient
from .proxies import current_remote_user_data_service
from .services.service import RemoteGroupDataService, RemoteUserDataService
from .tasks import do_user_data_update
from .utils import BrokerHelpers
from .views import (
    authorized,
    login,
)

OAUTH_ROUTE_REWRITES = {
    "/oauth/login/<remote_app>/": login,
    "/oauth/authorized/<remote_app>/": authorized,
}


def on_user_logged_out(_, user: User) -> None:
    """Send global logout signal to profiles API when user logs out."""
    kc_username = user.user_profile.get("identifier_kc_username")
    if not kc_username:
        kc_username = re.sub("knowledgeCommons", "", user.username, flags=re.IGNORECASE)
    current_remote_user_data_service.log_user_out_global(kc_username)


def on_user_logged_in(_, user: User) -> None:
    """Update user data from remote server when current user is changed."""
    # FIXME: Do we need this check now that we're using webhooks?

    with current_app.app_context():
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
        def _sso_silent_login_check() -> None:
            """Attempt transparent SSO login for anonymous users.

            If the user is anonymous and the TTL cookie has expired (or is
            absent), make a server-side request to the Profiles broker's
            silent-login endpoint. If an active session is found, decrypt
            the broker token, validate the nonce, and log the user in.

            Network errors or broker downtime are caught so they never
            block the original request.
            """
            if request.path.startswith(("/static/", "/api/", "/sso/broker-callback/")):
                return

            cu = current_user._get_current_object()
            if not getattr(cu, "is_anonymous", False):
                return

            cookie_name = current_app.config.get(
                "SSO_BROKER_COOKIE_NAME", "_sso_checked"
            )
            cookie_ttl = current_app.config.get("SSO_BROKER_COOKIE_TTL", 1800)
            cookie_val = request.cookies.get(cookie_name)
            if cookie_val:
                # Server-side TTL validation so we don't rely solely on
                # browser cookie expiry behavior.
                try:
                    checked_at = int(float(cookie_val))
                    if time.time() - checked_at < int(cookie_ttl):
                        return
                except (TypeError, ValueError):
                    # If the cookie value is unexpected, treat it as expired.
                    pass

            def _set_sso_cookie(response):
                response.set_cookie(
                    cookie_name,
                    str(int(time.time())),
                    max_age=cookie_ttl,
                    httponly=True,
                    secure=True,
                    samesite="Lax",
                )
                return response

            try:
                callback_url = url_for(
                    "invenio_remote_user_data_kcworks_sso.broker_callback",
                    _external=True,
                    _scheme="https",
                )
                data = SessionBrokerAPIClient.silent_login_check(
                    dict(request.cookies),
                    return_to=callback_url,
                    final_redirect=request.url,
                )

                if not data or "broker_token" not in data:
                    after_this_request(_set_sso_cookie)
                    return

                payload = BrokerHelpers.decrypt_broker_token(data["broker_token"])

                # Reject expired payloads as requested.
                exp = payload.get("exp")
                if exp is not None:
                    try:
                        if int(float(exp)) < int(time.time()):
                            after_this_request(_set_sso_cookie)
                            return
                    except (TypeError, ValueError):
                        after_this_request(_set_sso_cookie)
                        return

                nonce = payload.get("nonce")
                if not nonce or not BrokerHelpers.validate_nonce(nonce):
                    current_app.logger.warning("Silent login: nonce validation failed")
                    after_this_request(_set_sso_cookie)
                    return

                user, _ = BrokerHelpers.process_broker_payload(payload)
                if user:
                    login_user(user)
                    current_app.logger.info(
                        "Silent SSO login succeeded for user %s", user.id
                    )

                after_this_request(_set_sso_cookie)

            except Exception:
                current_app.logger.exception(
                    "Silent SSO login check failed unexpectedly"
                )
                after_this_request(_set_sso_cookie)


def finalize_app(app):
    """Finalize app."""
    for rule in app.url_map.iter_rules():
        route_str = str(rule)

        if route_str in OAUTH_ROUTE_REWRITES:
            if rule.endpoint in app.view_functions:
                app.view_functions[rule.endpoint] = OAUTH_ROUTE_REWRITES[route_str]
            else:
                app.logger.warning(
                    f"Warning: Endpoint '{rule.endpoint}' not "
                    f"found for overwriting route '{route_str}'"
                )
