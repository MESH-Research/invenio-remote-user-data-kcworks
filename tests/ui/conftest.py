# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Test configuration for UI tests."""

from collections.abc import Generator

import pytest
from flask import Flask
from invenio_app.factory import create_app as _create_app


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


@pytest.fixture(scope="module")
def base_app_with_templates(
    base_app: Flask, app_config, template_loader
) -> Generator[Flask, None, None]:
    """Profide a minimal app instance with template loader."""

    template_loader(base_app)

    yield base_app
