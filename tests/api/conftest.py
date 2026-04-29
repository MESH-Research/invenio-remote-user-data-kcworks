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
