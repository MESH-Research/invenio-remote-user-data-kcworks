"""Blueprint factories for invenio-remote-user-data-kcworks.

Invenio discovers and registers these via entry points, similarly to other
extensions (e.g. `invenio_base.api_blueprints` / `invenio_base.blueprints`).
"""

from flask import Blueprint, jsonify, make_response
from invenio_records_resources.services.errors import PermissionDeniedError
from werkzeug.exceptions import (
    BadRequest,
    Forbidden,
    MethodNotAllowed,
    NotFound,
    Unauthorized,
)

from .views import (
    RemoteUserDataUpdateWebhook,
    RemoteUserLogoutView,
    sso_broker_callback,
)


def create_api_blueprint(app):
    """Register blueprint on api app."""
    with app.app_context():
        blueprint = Blueprint(
            "invenio_remote_user_data_kcworks",
            __name__,
            # /api prefix already added because blueprint is registered
            # on the api app
        )

        # DEPRECATED: legacy webhook route
        blueprint.add_url_rule(
            "/webhooks/user_data_update",
            view_func=RemoteUserDataUpdateWebhook.as_view(
                f"{RemoteUserDataUpdateWebhook.view_name}_deprecated"
            ),
            methods=["GET", "POST"],
        )

        blueprint.add_url_rule(
            "/webhooks/users/update",
            view_func=RemoteUserDataUpdateWebhook.as_view(
                RemoteUserDataUpdateWebhook.view_name
            ),
            methods=["GET", "POST"],
        )

        blueprint.add_url_rule(
            "/webhooks/users/logout",
            view_func=RemoteUserLogoutView.as_view(
                RemoteUserLogoutView.view_name
            ),
            methods=["GET", "POST"],
        )

        # Register error handlers (JSON responses for API)
        blueprint.register_error_handler(
            Unauthorized,
            lambda e: make_response(
                jsonify({
                    "error": "Unauthorized",
                    "message": "Invalid, missing, or expired token.",
                    "status": 401,
                }),
                401,
            ),
        )
        blueprint.register_error_handler(
            PermissionDeniedError,
            lambda e: make_response(
                jsonify({
                    "error": "Forbidden",
                    "message": (
                        "The user does not have permission to perform this action."
                    ),
                    "status": 403,
                }),
                403,
            ),
        )
        blueprint.register_error_handler(
            NotFound,
            lambda e: make_response(
                jsonify({
                    "error": "Not Found",
                    "message": getattr(e, "description", str(e)),
                    "status": 404,
                }),
                404,
            ),
        )
        blueprint.register_error_handler(
            Forbidden,
            lambda e: make_response(
                jsonify({
                    "error": "Forbidden",
                    "message": str(e),
                    "status": 403,
                }),
                403,
            ),
        )
        blueprint.register_error_handler(
            BadRequest,
            lambda e: make_response(
                jsonify({
                    "error": "Bad Request",
                    "message": str(e),
                    "status": 400,
                }),
                400,
            ),
        )
        blueprint.register_error_handler(
            MethodNotAllowed,
            lambda e: make_response(
                jsonify({
                    "message": "Method not allowed",
                    "status": 405,
                }),
                405,
            ),
        )

    return blueprint


def create_sso_blueprint(app):
    """Blueprint for explicit broker callback routing."""
    # `app` is unused but kept for consistency with other factories.
    _ = app
    blueprint = Blueprint(
        "invenio_remote_user_data_kcworks_sso",
        __name__,
    )

    blueprint.add_url_rule(
        "/sso/broker-callback/",
        endpoint="broker_callback",
        view_func=sso_broker_callback,
        methods=["GET"],
    )

    return blueprint

