# Part of invenio-remote-user-data-kcworks.
# Copyright (C) 2024-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Pytest configuration for API tests.

Mirrors the small ``tests/api/conftest.py`` from the parent KCWorks
repository so that tests reaching for the ``headers`` (or
``headers_same_origin``) fixture continue to work whether the file is
discovered through the parent project's symlink or run directly from
this submodule.
"""

import pytest
from invenio_app.factory import create_api as _create_app


@pytest.fixture(scope="module")
def create_app(instance_path, entry_points):
    """Provide the application factory used to build the Flask app.

    Returns ``invenio_app.factory.create_api`` so that REST API blueprints
    registered under ``invenio_base.api_apps`` (e.g. the package's webhook
    receiver) are wired into the test app. See the module docstring for
    why this differs from the root KCWorks ``conftest.py``.

    Returns:
        Callable: The application factory function.
    """
    return _create_app


@pytest.fixture(scope="function")
def headers() -> dict:
    """Default headers for making JSON requests.

    Returns:
        dict: Default request headers.
    """
    return {
        "content-type": "application/json",
    }


@pytest.fixture(scope="function")
def headers_same_origin(headers, app_config) -> dict:
    """Headers with ``Referrer-Policy`` and ``Referer`` set to the same origin.

    Returns:
        dict: Default request headers plus same-origin ``Referer`` material.
    """
    headers["Referrer-Policy"] = "origin"
    headers["Referer"] = f"{app_config['SITE_UI_URL']}/"
    return headers
