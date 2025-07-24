# -*- coding: utf-8 -*-
#
# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

# from flask import render_template
from flask import (
    jsonify,
    make_response,
    current_app as app,
    g,
)
from flask.views import MethodView
from invenio_accounts.models import UserIdentity
from invenio_queues.proxies import current_queues
from werkzeug.exceptions import (
    BadRequest,
    Forbidden,
    MethodNotAllowed,
    NotFound,
    # Unauthorized,
)

from .signals import remote_data_updated

from invenio_remote_user_data_kcworks.proxies import (
    current_remote_user_data_service,
)

import base64
import json


from flask import (
    Blueprint,
    abort,
    current_app,
    redirect,
    request,
    url_for,
)
from flask_login import login_user
from flask_oauthlib.client import OAuthRemoteApp, OAuthException

from invenio_db import db
from invenio_oauthclient import current_oauthclient
from invenio_oauthclient.errors import OAuthRemoteNotFound
from invenio_oauthclient.handlers import (
    set_session_next_url,
)

from invenio_oauthclient.utils import (
    get_safe_redirect_target,
    serializer,
)

from invenio_oauthclient._compat import _create_identifier
from itsdangerous import BadData

from .api import APIResponse, fetch_user_profile
from .utils import CILogonHelpers


def _login(remote_app, authorized_view_name):
    """Send user to remote application for authentication."""
    oauth = current_oauthclient.oauth
    if remote_app not in oauth.remote_apps:
        raise OAuthRemoteNotFound()

    # Get redirect target in safe manner.
    next_param = get_safe_redirect_target(arg="next")

    # Redirect URI - must be registered in the remote service.
    # this will be used as a "next" parameter
    callback_url = url_for(
        authorized_view_name,
        remote_app=remote_app,
        _external=True,
        _scheme="https",
    )

    # Create a JSON Web Token that expires after OAUTHCLIENT_STATE_EXPIRES
    # seconds.
    state_token = base64.urlsafe_b64encode(
        json.dumps(
            {
                "app": remote_app,
                "next": next_param,
                "sid": _create_identifier(),
                "callback_next": callback_url,
            }
        ).encode()
    )

    # the path the user will take, here, will be:
    # here -> cilogon
    # cilogon -> https://profile.hcommons.org/cilogon/callback/
    # https://profile.hcommons.org/cilogon/callback/ -> callback_url
    # callback_url -> next_param
    return oauth.remote_apps[remote_app].authorize(
        callback="https://profile.hcommons.org/cilogon/callback/",
        state=state_token,
    )


def login(remote_app):
    """Send user to remote application for authentication."""
    if (
        current_app.config["OAUTHCLIENT_REMOTE_APPS"]
        .get(remote_app, {})
        .get("hide", False)
    ):
        abort(404)

    try:
        return _login(remote_app, ".authorized")
    except OAuthRemoteNotFound:
        return abort(404)


def _authorized(remote_app=None):
    """Authorized handler callback."""
    if remote_app not in current_oauthclient.handlers:
        return abort(404)

    state_token = request.args.get("state")

    data = json.loads(base64.urlsafe_b64decode(state_token).decode())

    # repack the state token in a way that Invenio uses
    state_token = serializer.dumps(
        {
            "next": data["next"],
            "sid": data["sid"],
            "app": data["app"],
        }
    )

    # Verify state parameter
    assert state_token
    # Checks authenticity and integrity of state and decodes the value.
    state = serializer.loads(state_token)
    # Verify that state is for this session, app and that next parameter
    # have not been modified.
    assert state["sid"] == _create_identifier()
    assert state["app"] == remote_app
    # Store next URL
    set_session_next_url(remote_app, state["next"])

    oauth = current_app.extensions.get("oauthlib.client")

    return _authorized_handler(oauth.remote_apps[remote_app])


def _authorized_handler(remote: OAuthRemoteApp, *args, **kwargs):
    """CILogon authorization handler."""
    """Contains: access_token, refresh_token, refresh_token_lifetime, id_token,
    token_type, expires_in, refresh_token_iat
    """
    resp = remote.authorized_response()

    # validate the token and extract the data fields
    decoded_token, id_token, sub = (
        CILogonHelpers.validate_token_and_extract_sub(resp)
    )

    # get user profile
    # contains: data, meta, next, previous
    result: APIResponse = fetch_user_profile(sub)

    # if the static bearer token is not authorized
    if not result.meta.authorized:
        raise abort(403)

    if result.data and len(result.data) > 0:
        # get the first user profile and log the user in or create a user

        # build an account_info dict that looks as expected
        account_info = CILogonHelpers.build_account_info(result, sub)

        # see if we have an existing user
        user = CILogonHelpers.get_user_from_account_info(account_info)
        if not user:
            user = CILogonHelpers.create_new_user(result)

        # link the user to the external id from cilogon
        CILogonHelpers.link_user_to_oauth_identifier(user, "cilogon", sub)

        # send the tokens to the storage API so that on logout they can be
        # revoked
        CILogonHelpers.update_token_data(resp, result)

        # update the user profile
        # "user_profile": dict(full_name=full_name, affiliations=affiliations),
        user.username = result.data[0].profile.username
        user.full_name = result.data[0].profile.name
        user.email = result.data[0].profile.email

        group_changes = CILogonHelpers.calculate_group_changes(result, user)
        user_changes, new_data = CILogonHelpers.calculate_user_changes(
            result, user
        )

        CILogonHelpers.update_local_user_data(
            user,
            new_data,
            user_changes,
            group_changes,
            **kwargs,
        )

        current_app.logger.debug(f"User changes: {user_changes}")
        current_app.logger.debug(f"Group changes: {group_changes}")
        db.session.commit()

        # log the user in!
        state_token = request.args.get("state")
        data = json.loads(base64.urlsafe_b64decode(state_token).decode())
        login_user(user)

        return redirect(data["next"])

    else:
        # redirect to the association service
        redirect_url = CILogonHelpers.build_association_url(id_token)

        current_app.logger.debug(f"Redirecting to: {redirect_url}")

        return redirect(redirect_url)


def authorized(remote_app=None):
    """Authorized handler callback."""
    try:
        return _authorized(remote_app)
    except OAuthRemoteNotFound:
        return abort(404)
    except (AssertionError, BadData):
        if current_app.config.get("OAUTHCLIENT_STATE_ENABLED", True) or (
            not (current_app.debug or current_app.testing)
        ):
            abort(403)
    except OAuthException as e:
        if e.type == "invalid_response":
            current_app.logger.warning(f"{e.message} ({e.data})")
            abort(500)
        else:
            raise


"""View for an invenio-remote-user-data-kcworks webhook receiver.

This view is used to receive webhook notifications from a remote IDP when
user or group data has been updated on the remote server. The view is
registered via an API blueprint on the Invenio instance.

This endpoint is not used to receive the actual data updates. It only receives
notifications that data has been updated. The actual data updates are
handled by a callback to the remote IDP's API.

One endpoint is exposed: https://example.org/api/webhooks/user_data_update/

Request methods
---------------

GET

A GET request to this endpoint will return a simple 200 response confirming
that the endpoint is active. No other action will be taken.

.. code-block:: bash

    curl -k -X GET https://example.org/api/webhooks/user_data_update
    --referer https://127.0.0.1 -H "Authorization: Bearer
    my-token-string"

POST

An update signal must be sent via a POST request to either endpoint. If
the signal is received successfully, the endpoint will return a 202 response
indicating that the notification has been accepted. This does NOT mean that the
data has been updated within Invenio. It only means that the notification has
been received. The actual data update is delegated to a background task which
may take some time to complete.

.. code-block:: bash

    curl -k -X POST https://example.org/api/webhooks/user_data_update
    --referer https://127.0.0.1 -d '{"users": [{"id": "1234",
    "event": "updated"}], "groups": [{"id": "4567", "event":
    "created"}]}' -H "Content-type: application/json" -H
    "Authorization: Bearer
    my-token-string"


Signal content
--------------

Notifications can be sent for multiple updates to multiple entities in a
single request. The signal body must be a JSON object whose top-level keys are

:idp: The name of the remote IDP that is sending the signal. This is a
      string that must match one of the keys in the
      REMOTE_USER_DATA_API_ENDPOINTS configuration variable.

:updates: A JSON object whose top-level keys are the types of data object that
          have been updated on the remote IDP. The value of each key is an
          array of objects representing the updated entities. Each of these
          objects should include an "id" property whose value is the entity's
          string identifier on the remote IDP. It should also include the
          "event" property, whose value is the type of event that is being
          signalled (e.g., "updated", "created", "deleted", etc.).

For example:

.. code-block:: json

    {
        "idp": "knowledgeCommons",
        "updates": {
            "users": [{"id": "1234", "event": "updated"},
                    {"id": "5678", "event": "created"}],
            "groups": [{"id": "1234", "event": "deleted"}]
        }
    }

Logging
-------

The view will log each POST request to the endpoint, each signal received,
and each task initiated to update the data. These logs will be written to a
dedicated log file, `logs/remote_data_updates.log`.

Endpoint security
-----------------

The endpoint is secured by a token that must be obtained by the remote IDP
and included in the request header.

"""


class RemoteUserDataUpdateWebhook(MethodView):
    """
    View class for the remote-user-data-kcworks webhook api endpoint.
    """

    # init_every_request = False  # FIXME: is this right?
    view_name = "remote_user_data_kcworks_webhook"

    def __init__(self):
        # self.webhook_token = os.getenv("REMOTE_USER_DATA_WEBHOOK_TOKEN")
        self.logger = app.logger

    def post(self):
        """
        Handle POST requests to the user data webhook endpoint.

        These are requests from a remote IDP indicating that user or group
        data has been updated on the remote server.
        """
        self.logger.debug(
            "****Received POST request to webhook endpoint again"
        )

        current_remote_user_data_service.require_permission(
            g.identity, "trigger_update"
        )

        try:
            data = request.get_json()
            idp = data["idp"]
            events = []
            config = app.config["REMOTE_USER_DATA_API_ENDPOINTS"][idp]
            entity_types = config["entity_types"]
            bad_entity_types = []
            bad_events = []
            users = []
            bad_users = []
            groups = []
            bad_groups = []

            for e in data["updates"].keys():
                if e in entity_types.keys():
                    for u in data["updates"][e]:
                        if u["event"] in entity_types[e]["events"]:
                            if e == "users":
                                user_identity = UserIdentity.query.filter_by(
                                    id=u["id"], method=idp
                                ).one_or_none()
                                if user_identity is None:
                                    bad_users.append(u["id"])
                                    self.logger.error(
                                        f"Received update signal from {idp} "
                                        f"for unknown user: {u['id']}"
                                    )
                                else:
                                    users.append(u["id"])
                                    events.append(
                                        {
                                            "idp": idp,
                                            "entity_type": e,
                                            "event": u["event"],
                                            "id": u["id"],
                                        }
                                    )
                            elif e == "groups":
                                groups.append(u["id"])
                                events.append(
                                    {
                                        "idp": idp,
                                        "entity_type": e,
                                        "event": u["event"],
                                        "id": u["id"],
                                    }
                                )
                        else:
                            bad_events.append(u)
                            self.logger.error(
                                f"{idp} Received update signal for "
                                f"unknown event: {u}"
                            )
                else:
                    bad_entity_types.append(e)
                    self.logger.error(
                        f"{idp} Received update signal for unknown "
                        f"entity type: {e}"
                    )
                    self.logger.error(data)

            if len(events) > 0:
                current_queues.queues["user-data-updates"].publish(events)
                remote_data_updated.send(
                    app._get_current_object(), events=events
                )
                self.logger.debug(
                    f"Published {len(events)} events to queue and emitted"
                    " remote_data_updated signal"
                )
                # self.logger.debug(events)
            else:
                if not users and bad_users or not groups and bad_groups:
                    entity_string = ""
                    if not users and bad_users:
                        entity_string += "users"
                    if not groups and bad_groups:
                        if entity_string:
                            entity_string += " and "
                        entity_string += "groups"
                    self.logger.error(
                        f"{idp} requested updates for {entity_string} that"
                        " do not exist"
                    )
                    self.logger.error(data["updates"])
                    raise NotFound(
                        "Updates attempted for unknown users or groups"
                    )
                elif not groups and bad_groups:
                    self.logger.error(
                        f"{idp} requested updates for groups that do not exist"
                    )
                    self.logger.error(data["updates"])
                    raise NotFound("Updates attempted for unknown groups")
                else:
                    self.logger.error(f"{idp} No valid events received")
                    self.logger.error(data["updates"])
                    raise BadRequest("No valid events received")

            # return error message after handling signals that are
            # properly formed
            if len(bad_entity_types) > 0 or len(bad_events) > 0:
                # FIXME: raise better error, since request isn't
                # completely rejected
                raise BadRequest
        except KeyError:  # request is missing 'idp' or 'updates' keys
            self.logger.error(f"Received malformed signal: {request.data}")
            raise BadRequest(
                "Received malformed signal. Missing 'idp' or 'updates' keys."
            )

        return (
            jsonify(
                {
                    "message": "Webhook notification accepted",
                    "status": 202,
                    "updates": data["updates"],
                }
            ),
            202,
        )

    def get(self):
        self.logger.debug("****Received GET request to webhook endpoint")
        return (
            jsonify({"message": "Webhook receiver is active", "status": 200}),
            200,
        )

    def put(self):
        raise MethodNotAllowed

    def delete(self):
        raise MethodNotAllowed


def create_api_blueprint(app):
    """Register blueprint on api app."""

    with app.app_context():
        blueprint = Blueprint(
            "invenio_remote_user_data_kcworks",
            __name__,
            # /api prefix already added because blueprint is registered
            # on the api app
        )

        # routes = app.config.get("APP_RDM_ROUTES")

        blueprint.add_url_rule(
            "/webhooks/user_data_update",
            view_func=RemoteUserDataUpdateWebhook.as_view(
                RemoteUserDataUpdateWebhook.view_name
            ),
            methods=["GET", "POST"],
        )

        # Register error handlers
        blueprint.register_error_handler(
            Forbidden,
            lambda e: make_response(
                jsonify({"error": "Forbidden", "status": 403}), 403
            ),
        )
        blueprint.register_error_handler(
            BadRequest,
            lambda e: make_response(
                jsonify({"error": "Bad Request", "status": 400}), 400
            ),
        )
        blueprint.register_error_handler(
            MethodNotAllowed,
            lambda e: make_response(
                jsonify({"message": "Method not allowed", "status": 405}), 405
            ),
        )

    return blueprint
