# -*- coding: utf-8 -*-
#
# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

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

# from flask import render_template
from crypt import methods

from flask import (
    Blueprint,
)
from flask import current_app as app
from flask import (
    jsonify,
    make_response,
    request,
)
from flask.views import MethodView
from invenio_accounts.models import UserIdentity
from invenio_queues.proxies import current_queues
from werkzeug.exceptions import (  # Unauthorized,
    BadRequest,
    Forbidden,
    MethodNotAllowed,
    NotFound,
)

from .signals import remote_data_updated


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
                    # self.logger.debug(
                    #     f"In POST view: Received {e} update signal from "
                    #     f"{idp}: {data['updates'][e]}"
                    # )
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
