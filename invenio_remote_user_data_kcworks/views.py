# -*- coding: utf-8 -*-
#
# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

import base64
import contextlib
import json
from pprint import pformat

import requests
from flask import (
    Blueprint,
    abort,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    Response,
    url_for,
)
from flask import (
    current_app as app,
)
from flask.views import MethodView
from flask_login import login_user
from flask_oauthlib.client import OAuthException, OAuthRemoteApp
from invenio_access.permissions import system_identity
from invenio_accounts.errors import AlreadyLinkedError
from invenio_accounts.models import UserIdentity
from invenio_db import db
from invenio_oauthclient import current_oauthclient
from invenio_oauthclient._compat import _create_identifier
from invenio_oauthclient.errors import OAuthRemoteNotFound
from invenio_oauthclient.handlers import (
    set_session_next_url,
)
from invenio_oauthclient.utils import (
    get_safe_redirect_target,
    serializer,
)
from invenio_queues.proxies import current_queues
from invenio_remote_user_data_kcworks.errors import (
    IDTokenInvalid,
    StateTokenInvalid,
    UserDataRequestFailed,
    UserDataRequestTimeout,
)
from invenio_remote_user_data_kcworks.proxies import (
    current_remote_user_data_service,
)
from itsdangerous import BadData
from werkzeug.exceptions import (
    BadRequest,
    Forbidden,
    MethodNotAllowed,
    NotFound,
    Unauthorized,
)

from .api import APIResponse, fetch_user_profile
from .signals import remote_data_updated
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
        json.dumps({
            "app": remote_app,
            "next": next_param,
            "sid": _create_identifier(),
            "callback_next": callback_url,
        }).encode()
    )

    # the path the user will take, here, will be:
    # here -> cilogon
    # cilogon -> https://profile.hcommons.org/cilogon/callback/
    # https://profile.hcommons.org/cilogon/callback/ -> callback_url
    # callback_url -> next_param
    try:
        return oauth.remote_apps[remote_app].authorize(
            callback=app.config.get(
                "IDMS_CALLBACK_URL",
                f"{app.config.get('COMMONS_API_REQUEST_PROTOCOL')}://{app.config.get('KC_PROFILES_DOMAIN')}/cilogon/callback/",
            ),
            state=state_token,
        )
    except JSONDecodeError:
        abort(500)


def login(remote_app):
    """Send user to remote application for authentication.

    The blueprint for this view function is registered in invenio_oauthclient/
    views/client.py but we (in ext.py) override the route to lead to this
    function instead of the default function provided in invenio_oauthclient.
    """
    if app.config["OAUTHCLIENT_REMOTE_APPS"].get(remote_app, {}).get("hide", False):
        abort(404)

    try:
        return _login(remote_app, ".authorized")
    except OAuthRemoteNotFound:
        abort(404)


def _authorized(remote_app: str | None = None) -> Response:
    """Authorized handler callback.

    Arguments:
        remote_app (str): The name of the remote app returning the
            authorized response, matching a key in the configuration
            for oauth remote apps.

    Raises:
        OAuthRemoteNotFound: If the remote_app doesn't match any
            configured remote oauth app.
        StateTokenInvalid: If the state token returned is invalid,
            either because it is malformed, its `app` doesn't match
            the remote_app name, or the `sid` doesn't match the unique
            session id that was sent with the token when the login
            was initiated.

    Returns:
        Response: Redirects to a Flask/Werkzeug Response.
    """
    if remote_app not in current_oauthclient.handlers:
        raise OAuthRemoteNotFound()

    state_token = request.args.get("state")

    try:
        data = json.loads(base64.urlsafe_b64decode(state_token).decode())

        # repack the state token in a way that Invenio uses
        state_token = serializer.dumps({
            "next": data["next"],
            "sid": data["sid"],
            "app": data["app"],
        })

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
    except (AssertionError, BadData) as e:
        app.logger.warning("OAuth state token validation failed in authorized handler.")
        raise StateTokenInvalid from e

    oauth = app.extensions.get("oauthlib.client")

    return _authorized_handler(oauth.remote_apps[remote_app])


def _authorized_handler(remote: OAuthRemoteApp, *args, **kwargs) -> Response:
    """CILogon authorization handler.

    Arguments:
        remote (OAuthRemoteApp): The invenio_oauthclient app object that
            carries the oauth configuration and token exchange method.

    Returns:
        Response: Redirects to a Flask/Werkzeug Response.
    """
    resp = remote.authorized_response()
    # JSON response contains: access_token, refresh_token, refresh_token_lifetime,
    # id_token, token_type, expires_in, refresh_token_iat

    # Validate the token and extract the data fields
    decoded_token, id_token, sub = CILogonHelpers.validate_token_and_extract_sub(resp)

    # Get user profile APIResponse
    # contains: data, meta, next, previous
    profile_response: APIResponse | None = None
    try:
        profile_response = fetch_user_profile(sub_id=sub)
    except requests.Timeout as e:
        raise UserDataRequestTimeout from e
    except requests.RequestException as e:
        raise UserDataRequestFailed from e

    # If the static bearer token is not authorized
    if (
        profile_response
        and profile_response.meta
        and not profile_response.meta.authorized
    ):
        raise UserDataRequestFailed(
            message="Bearer token for user data endpoint was not accepted."
        )

    # Combine account data available so we can look up user
    account_info = CILogonHelpers.build_account_info(profile_response, sub)

    # See if we have an existing user
    # If profile api request fails we can still get from
    # sub and UserIdentity table
    user = CILogonHelpers.get_user_from_account_info(account_info)

    if profile_response:
        # if the profile lookup succeeds...
        # get the first user matching user and log the user in or create a user
        if profile_response.data and len(profile_response.data) > 0:
            if not user:
                user = CILogonHelpers.create_new_user(profile_response)

            # link the user to the external id from cilogon
            with contextlib.suppress(AlreadyLinkedError):
                CILogonHelpers.link_user_to_oauth_identifier(user, "cilogon", sub)

            # send the tokens to the storage API so that on logout they can be
            # revoked
            CILogonHelpers.update_token_data(resp, profile_response)

            # update user data with pre-fetched remote response
            current_remote_user_data_service.update_user_from_remote(
                system_identity,
                user.id,
                "knowledgeCommons",
                sub,
                remote_data=profile_response,
            )

            # log the user in!
            state_token = request.args.get("state")
            data = json.loads(base64.urlsafe_b64decode(state_token).decode())
            login_user(user)

            return redirect(data["next"])

        else:
            # No matching KC member was found. They need to associate their login
            # with a KC account before logging in here and linking/creating a
            # KCWorks account.
            redirect_url = CILogonHelpers.build_association_url(id_token)

            return redirect(redirect_url)

    elif user:
        # User has a valid KCWorks account but member API failed.
        # If the profile lookup failed because the API call failed
        # we don't send them to the association service because we
        # don't know the status of their KC account. If the user was
        # not *found* we will have a profile_response without data
        # and end up in the other code path above.
        state_token = request.args.get("state")
        data = json.loads(base64.urlsafe_b64decode(state_token).decode())

        # Log them in since they have a valid KCWorks account
        login_user(user)

        return redirect(data["next"])

    else:
        abort(
            401,
            description=error_message,
        )


def authorized(remote_app: str | None = None):
    """Authorized handler callback.

    The blueprint for this view function is registered in invenio_oauthclient/
    views/client.py but we (in ext.py) override the route to lead to this
    function instead of the default function provided in invenio_oauthclient.

    Arguments:
        remote_app (str): The name of the oauth remote app set
            up in the config for oauth remote apps.
    """
    try:
        return _authorized(remote_app)
    except OAuthRemoteNotFound:
        abort(
            401,
            description=(
                f"A remote oauth response was received for an app that is not "
                f"in current_oauthclient.handlers: {remote_app}"
            ),
        )
    except OAuthException as e:
        if e.type == "invalid_response":
            app.logger.error(f"{e.message} ({e.data})")
            abort(
                401,
                description=app.config.get(
                    "REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_FAILURE"
                ).format(message=e.message),
            )
        else:
            raise e
    except Exception as e:
        app.logger.error(
            f"Unhandled error raised during OAuth login: {e}", exc_info=True
        )


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
        # FIXME: Is the webhook token used?
        # self.webhook_token = os.getenv("REMOTE_USER_DATA_WEBHOOK_TOKEN")
        self.logger = app.logger

    def post(self):
        """
        Handle POST requests to the user data webhook endpoint.

        These are requests from a remote IDP indicating that user or group
        data has been updated on the remote server.
        """
        current_remote_user_data_service.require_permission(
            g.identity, "trigger_update"
        )

        try:
            data = request.get_json()
            idp = data["idp"]
            auth_method = idp
            if idp == "knowledgeCommons":
                # FIXME: Allow for multiple KC auth methods
                auth_method = app.config["KC_REMOTE_IDPS"][0]
            events = []
            idp_config = app.config["REMOTE_USER_DATA_API_ENDPOINTS"][idp]
            entity_types = idp_config["entity_types"]
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
                                    id=u["id"], method=auth_method
                                ).one_or_none()
                                if user_identity is None:
                                    bad_users.append(u["id"])
                                    self.logger.error(
                                        f"Received update signal from {idp} "
                                        f"for unknown user: external id {u['id']}"
                                    )
                                else:
                                    self.logger.error(
                                        f"user_identity: {user_identity.id_user}, {user_identity.id}"
                                    )
                                    users.append(u["id"])
                                    events.append({
                                        "idp": idp,
                                        "entity_type": e,
                                        "event": u["event"],
                                        "oauth_id": user_identity.id,
                                        "user_id": user_identity.id_user,
                                    })
                            elif e == "groups":
                                groups.append(u["id"])
                                events.append({
                                    "idp": idp,
                                    "entity_type": e,
                                    "event": u["event"],
                                    "id": u["id"],
                                })
                        else:
                            bad_events.append(u)
                            self.logger.error(
                                f"{idp} Received update signal for unknown event: {u}"
                            )
                else:
                    bad_entity_types.append(e)
                    self.logger.error(
                        f"{idp} Received update signal for unknown entity type: {e}"
                    )
                    self.logger.error(data)

            if len(events) > 0:
                current_queues.queues["user-data-updates"].publish(events)
                remote_data_updated.send(app._get_current_object(), events=events)
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
                        f"{idp} requested updates for {entity_string} that do not exist"
                    )
                    self.logger.error(data["updates"])
                    raise NotFound("Updates attempted for unknown users or groups")
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
            jsonify({
                "message": "Webhook notification accepted",
                "status": 202,
                "updates": data["updates"],
            }),
            202,
        )

    def get(self):
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
