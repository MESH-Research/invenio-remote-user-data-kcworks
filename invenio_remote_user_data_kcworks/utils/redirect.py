# This file is part of the invenio-remote-user-data-kcworks package.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see
# LICENSE file for more details.

"""Open-redirect-safe URL normalisation."""

from flask import current_app as app
from flask import request
from uritools import uricompose, urisplit


def safe_redirect_target(target: str | None = None, arg_name: str | None = None) -> str:
    """Validate and normalize a redirect target to avoid open redirects.

    If no redirect target is specified, returns the validated request referrer
    if possible.

    Default fallback is to return the root path ('/').

    Arguments:
        target (str|None): A url string for the redirect target.
        arg_name (str|None): A string name for a request argument that carries the
          redirect url.

    Returns:
        str: The safe target for the redirect.
    """
    if not target:
        target = request.args.get(arg_name, "") if arg_name else ""
    allowed_hosts = app.config.get("TRUSTED_HOSTS") or []

    if not allowed_hosts:
        app.logger.error("TRUSTED_HOSTS not configred. Cannot validate redirects.")
        return "/"

    for redirect_target in (target, request.referrer):
        if not redirect_target:
            continue

        redirect_uri = urisplit(redirect_target)
        # Check if full url is allowed
        if redirect_uri.host and redirect_uri.host in allowed_hosts:
            return redirect_target
        # Handle relative paths safely
        elif redirect_uri.path:
            return uricompose(
                path=redirect_uri.getpath(),
                query=redirect_uri.getquery(),
                fragment=redirect_uri.getfragment(),
            )

    return "/"
