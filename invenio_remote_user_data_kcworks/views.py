# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""HTTP views for SSO broker flows and remote user-data webhooks."""

import time
from typing import Any, NoReturn, cast
from urllib.parse import urlencode

from flask import (
    Response,
    abort,
    g,
    jsonify,
    redirect,
    request,
    url_for,
)
from flask import (
    current_app as app,
)
from flask.views import MethodView
from flask_login import login_user
from invenio_accounts.models import User, UserIdentity
from invenio_accounts.sessions import delete_user_sessions
from invenio_db import db
from invenio_queues.proxies import current_queues
from invenio_remote_user_data_kcworks.proxies import (
    current_remote_user_data_service,
)
from werkzeug.exceptions import (
    BadRequest,
    MethodNotAllowed,
    NotFound,
)
from werkzeug.local import LocalProxy

from .errors import (
    BrokerExpiryValueError,
    BrokerNonceValidationError,
    BrokerPayloadExpiredError,
    BrokerPayloadProcessingError,
    BrokerTokenDecryptionError,
    BrokerTokenMissingError,
    UserDataRequestFailed,
    UserDataRequestTimeout,
)
from .signals import remote_data_updated
from .utils.auth import CILogonHelpers
from .utils.broker import BrokerHelpers
from .utils.redirect import safe_redirect_target


def sso_broker_login(
    next: str | None = None, silent: bool = False, **kwargs: Any
) -> Response:
    """Redirect the user to the Profiles broker login endpoint.

    Flask-Security will send us here as security.login and supplies the
    final destination in the 'next' query parameter. The invenio-remote-user-
    -data-kcworks silent login check (in ext.py) also sends an anonymous
    user here before the request is handled.

    In both cases, this function should be transparent and *does not
    actually render any view template or expose any endpoint*. It simply passes
    the request on to the Profiles broker to handle auth.

    Parameters:
        next (str | None): The url where the user should be redirected after a
            successful session broker response. In the case of silent login the
            user will be returned here on failure as well.
        silent (bool): Whether the user should be offered a login page on Profiles
            if they do not have an existing session, or whether they should be
            silently returned without login.
        **kwargs: Ignored; accepted for call compatibility.

    Returns:
        Response: A 302 redirect to the Profiles broker login or silent-login URL
            with return_to and final_redirect query parameters.

    Note:
        Calls ``abort(500)`` if the broker URL is not configured.
    """
    broker_url = ""
    if silent:
        broker_url = app.config.get("SSO_BROKER_SILENT_LOGIN_URL")
        if not broker_url:
            abort(500, message="SSO_BROKER_SILENT_LOGIN_URL not configured")
    else:
        broker_url = app.config.get("SSO_BROKER_LOGIN_URL")
        if not broker_url:
            abort(500, message="SSO_BROKER_LOGIN_URL is not configured")

    final_redirect = safe_redirect_target(target=next, arg_name="next")

    return_to = url_for(
        "invenio_remote_user_data_kcworks_sso.broker_callback",
        _external=True,
        _scheme="https",
    )

    query = urlencode({"return_to": return_to, "final_redirect": final_redirect})
    # Type checkers wrongly complain that the return isn't Flask.wrappers.Response
    return cast(Response, redirect(f"{broker_url}?{query}"))


def _sso_broker_callback() -> Response:
    """Handle broker callback after explicit login or silent login.

    Expects an encrypted broker_token query parameter, or a no_session
    branch for silent login without a session.

    Returns:
        Response: A redirect to the validated final_redirect target. On
            successful login, the broker retry cookie is cleared on the
            response; on the no-session path, the retry cookie is set.

    Raises:
        BrokerTokenMissingError: If neither broker_token nor no_session
            is present.
        BrokerTokenDecryptionError: If the token cannot be decrypted.
        BrokerPayloadExpiredError: If the token payload is expired.
        BrokerExpiryValueError: If the expiry value is invalid.
        BrokerNonceValidationError: If the nonce is missing or invalid.
        BrokerPayloadProcessingError: If the user cannot be resolved from
            the payload.
        UserCreationFailed: If new user creation fails.
        UserDataRequestTimeout: Propagated from profile fetch.
        UserDataRequestFailed: Propagated from profile fetch.
    """
    broker_token = request.args.get("broker_token")
    no_session = request.args.get("no_session")
    final_redirect = request.args.get("final_redirect")

    if not broker_token and not no_session:
        app.logger.error("Broker callback called without broker_token")
        raise BrokerTokenMissingError

    elif broker_token and not no_session:
        try:
            user, final_redirect = BrokerHelpers().process_broker_payload(broker_token)

            if not user:
                app.logger.error("Could not find or create user from broker payload")
                raise BrokerPayloadProcessingError

            login_user(user)
        except UserDataRequestTimeout as e:
            raise e
        except UserDataRequestFailed as e:
            raise e

        response = redirect(safe_redirect_target(final_redirect))
        return BrokerHelpers.clear_broker_refresh_cookie(response)

    else:
        response = redirect(safe_redirect_target(final_redirect))
        return BrokerHelpers.set_broker_refresh_cookie(response)


def sso_broker_callback() -> Response:
    """Handle broker callback after explicit login or silent login.

    Expects an encrypted broker_token query parameter (or silent-login
    no_session flow). Maps broker errors to HTTP responses where
    appropriate.

    Returns:
        Response: Same as _sso_broker_callback on success.

    Raises:
        BrokerTokenMissingError: Re-raised from the inner handler.
        BrokerTokenDecryptionError: Re-raised from the inner handler.
        BrokerPayloadExpiredError: Re-raised from the inner handler.
        BrokerExpiryValueError: Re-raised from the inner handler.
        BrokerNonceValidationError: Re-raised from the inner handler.

    Note:
        ``UserDataRequestTimeout`` and ``UserDataRequestFailed`` may propagate
        from profile resolution inside ``_sso_broker_callback``.
        BrokerPayloadProcessingError is not propagated; it becomes
        ``abort(401)`` with ``REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_FAILURE``.
        Other exceptions may propagate for framework error handling.
    """
    try:
        return _sso_broker_callback()
    except BrokerTokenMissingError:
        raise
    except BrokerTokenDecryptionError:
        raise
    except BrokerPayloadExpiredError:
        raise
    except BrokerExpiryValueError:
        raise
    except BrokerNonceValidationError:
        raise
    except BrokerPayloadProcessingError:
        abort(
            401,
            message=app.config.get(
                "REMOTE_USER_DATA_ERROR_MESSAGE_LOGIN_FAILURE",
                "Login failed",
            ),
        )
    # Other errors handled automatically (see kcworks.ext)
    except Exception as e:
        raise e


class RemoteUserDataUpdateWebhook(MethodView):
    """View class for the user/group data update webhook receiver.

    This view is registered for both ``/api/webhooks/users/update`` (preferred)
    and ``/api/webhooks/user_data_update`` (deprecated, still operational). It
    receives webhook notifications from a remote IDP when user or group data has
    been updated on the remote server.

    This endpoint is not used to receive the actual data updates. It only receives
    notifications that data has been updated. The actual data updates are
    handled by a callback to the remote IDP's API.

    Request methods
    ---------------

    GET

    A GET request to either URL will return a simple 200 response confirming
    that the endpoint is active. No other action will be taken.

    .. code-block:: bash

        curl -k -X GET https://example.org/api/webhooks/users/update \
            --referer https://127.0.0.1 -H 'Authorization: Bearer my-token-string'

    POST

    An update signal must be sent via a POST request to either endpoint. If
    the signal is received successfully, the endpoint will return a 202 response
    indicating that the notification has been accepted. This does NOT mean that the
    data has been updated within Invenio. It only means that the notification has
    been received. The actual data update is delegated to a background task which
    may take some time to complete. Prefer /api/webhooks/users/update; use of
    /api/webhooks/user_data_update is deprecated.

    .. code-block:: bash

        curl -k -X POST https://example.org/api/webhooks/users/update \
            --referer https://127.0.0.1 \
            -H 'Content-type: application/json' \
            -H 'Authorization: Bearer my-token-string' \
            -d '{
                "users": [{"id": "1234", "event": "updated"}],
                "groups": [{"id": "4567", "event": "created"}]
            }'

    Lazy provisioning
    -----------------

    We accept ``created`` events for users that do not yet have
    a ``UserIdentity``, and treat ``updated`` events for unknown users
    as ``created`` so that we still provision them. (The downstream task will fetch
    the profile and create the local user.) An ``updated`` signal for an unknown
    user usually means we missed the original ``created`` webhook for that user, 
    or they were registered prior to the current IDMS system setup. We just
    log a warning to flag the gap for operators in case a genuine problem emerges.

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
              objects should include an 'id' property whose value is the entity's
              string identifier on the remote IDP. It should also include the
              'event' property, whose value is the type of event that is being
              signalled (e.g., 'updated', 'created', 'deleted', etc.).

              For ``users`` events the ``id`` is the OAuth ``sub``
              for the user on the remote IDP (i.e. the value stored
              as ``UserIdentity.id``). The KC member name needed for
              the ``/api/v1/members/{member_name}/works/status``
              callback is resolved locally from the sub via
              ``UserIdentity`` -> ``User.user_profile['identifier_kc_username']``
              when the callback fires.

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

    Endpoint security
    -----------------

    The endpoint is secured by a token that must be obtained by the remote IDP
    and included in the request header.

    """

    view_name = "remote_user_data_kcworks_webhook"

    def __init__(self) -> None:
        """Attach the Flask app logger for this view."""
        #  NOTE: The old static webhook token is no longer used.
        # The endpoint is protected by account-related OAuth tokens.
        self.logger = app.logger

    def post(self) -> tuple[Response, int]:
        """Handle POST requests to the user data webhook endpoint.

        These are requests from a remote IDP indicating that user or group
        data has been updated on the remote server.

        Returns:
            tuple[Response, int]: JSON body and HTTP 202 when the
            notification is accepted and queued.

        Raises:
            werkzeug.exceptions.BadRequest: Malformed JSON or no valid events.
            werkzeug.exceptions.NotFound: Updates referenced unknown users/groups
                in specific edge cases.
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
                                    if u["event"] != "created":
                                        self.logger.warning(
                                            f"{idp} sent an {u['event']!r} "
                                            f"event for unknown user (sub="
                                            f"{u['id']!r}); converting to "
                                            "'created' for lazy provisioning"
                                        )
                                    users.append(u["id"])
                                    events.append({
                                        "idp": idp,
                                        "entity_type": e,
                                        "event": "created",
                                        "oauth_id": u["id"],
                                        "user_id": None,
                                    })
                                else:
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
                            self.logger.warning(
                                f"{idp} Received update signal for unknown event: {u}"
                            )
                else:
                    bad_entity_types.append(e)
                    self.logger.warning(
                        "%s received update signal for unknown entity "
                        "type %r (configured types: %s)",
                        idp,
                        e,
                        sorted(entity_types.keys()),
                    )

            if len(events) > 0:
                current_queues.queues["user-data-updates"].publish(events)
                remote_data_updated.send(
                    cast(LocalProxy, app)._get_current_object(), events=events
                )
            else:
                if not users and bad_users or not groups and bad_groups:
                    entity_string = ""
                    if not users and bad_users:
                        entity_string += "users"
                    if not groups and bad_groups:
                        if entity_string:
                            entity_string += " and "
                        entity_string += "groups"
                    self.logger.info(
                        f"{idp} requested updates for {entity_string} that do not exist"
                    )
                    self.logger.info(data["updates"])
                    raise NotFound("Updates attempted for unknown users or groups")
                elif not groups and bad_groups:
                    self.logger.info(
                        f"{idp} requested updates for groups that do not exist"
                    )
                    self.logger.info(data["updates"])
                    raise NotFound("Updates attempted for unknown groups")
                else:
                    summary = {
                        bucket: {
                            "count": len(items),
                            "triples": [
                                (
                                    bucket,
                                    str(it.get("event")),
                                    str(it.get("id")),
                                )
                                for it in items
                            ],
                        }
                        for bucket, items in (data.get("updates") or {}).items()
                        if isinstance(items, list)
                    }
                    self.logger.warning(
                        "%s no valid events received; summary=%s",
                        idp,
                        summary,
                    )
                    raise BadRequest("No valid events received")

            # return error message after handling signals that are
            # properly formed
            if len(bad_entity_types) > 0 or len(bad_events) > 0:
                # FIXME: raise better error, since request isn't
                # completely rejected
                raise BadRequest
        except KeyError:  # request is missing 'idp' or 'updates' keys
            raw_body = request.data or b""
            excerpt = raw_body[:400]
            self.logger.error(
                "Received malformed signal (Content-Type=%r, Content-Length=%d): %r%s",
                request.content_type,
                len(raw_body),
                excerpt,
                "..." if len(raw_body) > len(excerpt) else "",
            )
            raise BadRequest(
                "Received malformed signal. Missing 'idp' or 'updates' keys."
            ) from None

        return (
            jsonify({
                "message": "Webhook notification accepted",
                "status": 202,
                "updates": data["updates"],
            }),
            202,
        )

    def get(self) -> tuple[Response, int]:
        """Confirm the webhook endpoint is reachable.

        Returns:
            tuple[Response, int]: JSON body and HTTP 200.
        """
        return (
            jsonify({"message": "Webhook receiver is active", "status": 200}),
            200,
        )

    def put(self) -> NoReturn:
        """Reject PUT; this endpoint only supports GET and POST.

        Raises:
            MethodNotAllowed: Always, because PUT is not implemented.
        """
        raise MethodNotAllowed()

    def delete(self) -> NoReturn:
        """Reject DELETE; this endpoint only supports GET and POST.

        Raises:
            MethodNotAllowed: Always, because DELETE is not implemented.
        """
        raise MethodNotAllowed()


class RemoteUserLogoutView(MethodView):
    """View class for the user logout signal receiver.

    This view is used to receive the webhook signal from the central
    KC IDMS to log a user out from KCWorks when they have been logged out on
    another app in the network.

    Request methods
    ---------------

    GET

    A GET request to this endpoint will return a simple 200 response confirming
    that the endpoint is active. No other action will be taken.

    .. code-block:: bash

        curl -k -X GET https://example.org/api/webhooks/users/logout
        --referer https://127.0.0.1 -H 'Authorization: Bearer my-token-string'

    POST

    An actual logout signal must be sent via a POST request with a username query
    parameter. If the signal is received successfully, the endpoint will return a
    200 response with a JSON body confirming that the user has been logged out.

    .. code-block:: bash

        curl -k -X POST \
            'https://example.org/api/webhooks/users/logout?username=john_doe' \
            --referer https://127.0.0.1 \
            -H 'Content-type: application/json' \
            -H 'Authorization: Bearer my-token-string'

    Endpoint security
    -----------------

    The endpoint is secured by a Bearer token that must be provided in the
    Authorization request header.

    """

    view_name = "remote_user_data_kcworks_logout_webhook"

    def __init__(self) -> None:
        """Attach the Flask app logger for this view."""
        self.logger = app.logger

    def post(self) -> tuple[Response, int]:
        """Handle POST requests to the user logout webhook endpoint.

        Invalidates KCWorks sessions for every matching user (single user or
        list from KC username lookup).

        Authentication is by static bearer token, handled by the configurable
        routes in STATIC_API_TOKEN_ROUTES and the before_request handler
        registered by kcworks.ext.

        Returns:
            tuple[Response, int]: JSON body and status 200 when sessions
            were invalidated, 404 when no user matches the username query
            parameter, or 500 on persistence errors.

        Raises:
            werkzeug.exceptions.BadRequest: If the username query parameter
                is missing.
        """
        current_remote_user_data_service.require_permission(
            g.identity, "trigger_logout_user"
        )

        kc_username = request.args.get("username")
        if not kc_username:
            raise BadRequest("Missing required query parameter: username")

        user = CILogonHelpers.try_get_user_by_kc_username(kc_username, "cilogon")
        if isinstance(user, User):
            user = [user]
        if not user:
            self.logger.info(
                f"Logout webhook: no user found for username={kc_username!r}"
            )
            return (
                jsonify({
                    "message": (
                        f"User {kc_username} not found in KCWorks; "
                        "no sessions invalidated"
                    ),
                    "status": "not found",
                }),
                404,
            )

        try:
            for u in user:
                sessions_count = len(u.active_sessions)
                delete_user_sessions(u)
                db.session.commit()
        except Exception as e:
            self.logger.error(
                f"Logout webhook: failed to invalidate sessions for "
                f"username={kc_username!r}: {e}",
                exc_info=True,
            )
            db.session.rollback()
            return (
                jsonify({
                    "message": f"Failed to log out {kc_username}",
                    "status": "error",
                }),
                500,
            )

        self.logger.debug(
            f"Logout webhook: invalidated {sessions_count} session(s) for user "
            f"{user} (username={kc_username!r})"
        )
        return (
            jsonify({
                "message": f"User {kc_username} logged out",
                "status": "success",
            }),
            200,
        )

    def get(self) -> tuple[Response, int]:
        """Confirm the logout webhook endpoint is reachable.

        Returns:
            tuple[Response, int]: JSON body and HTTP 200.
        """
        return (
            jsonify({"message": "Webhook receiver is active", "status": 200}),
            200,
        )

    def put(self) -> NoReturn:
        """Reject PUT; this endpoint only supports GET and POST.

        Raises:
            MethodNotAllowed: Always, because PUT is not implemented.
        """
        raise MethodNotAllowed()

    def delete(self) -> NoReturn:
        """Reject DELETE; this endpoint only supports GET and POST.

        Raises:
            MethodNotAllowed: Always, because DELETE is not implemented.
        """
        raise MethodNotAllowed()


# NOTE: API/UI blueprint factories live in
# invenio_remote_user_data_kcworks.blueprints.
