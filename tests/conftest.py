# Part of invenio-remote-user-data-kcworks.
# Copyright (C) 2023-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file
# for more details.

"""Top-level pytest configuration for invenio-remote-user-data-kcworks tests.

This conftest mirrors the structure used by the sibling KCWorks packages, so
that fixture composition stays consistent across the family. Two intentional
differences from the root KCWorks `conftest.py`:

1. `create_app` returns `invenio_app.factory.create_api` (not
   `create_app`). The package's own tests focus on REST API resources
   and CLI commands; using `create_api` lets us exercise blueprints
   registered under `invenio_base.api_apps` without spinning up the
   UI app.
2. Shared `app_config` from `kcworks-test-fixtures` supplies the common
   test baseline (including IDMS/SSO defaults); this conftest only wraps
   it for package-specific keys (no `invenio.cfg`).

Per the agreed plan, duplicate vocabulary/user/role fixtures previously
defined here were removed in favour of the shared fixture modules vendored
from `kcworks-test-fixtures` (the `tests/fixtures` submodule). One
`COMMUNITIES_SERVICE_COMPONENTS` override remains so API-only tests match
KCWorks community visibility behaviour without loading the full KCWorks
extension.
"""

from collections.abc import Generator
from pathlib import Path

import pytest
from invenio_app.factory import create_api as _create_app
from invenio_communities.communities.services.components import (
    CommunityAccessComponent as BaseCommunityAccessComponent,
)
from invenio_rdm_records.services.communities.components import (
    CommunityAccessComponent as RDMCommunityAccessComponent,
)
from invenio_rdm_records.services.communities.components import (
    CommunityServiceComponents,
)

from tests.fixtures.app import RunningApp  # noqa: F401 — re-export for tests
from tests.fixtures.idms import register_idms_static_api_token_before_request

pytest_plugins = (
    "celery.contrib.pytest",
    # "tests.fixtures.caching",  # depends on invenio-stats-dashboard
    "tests.fixtures.app",
    "tests.fixtures.app_config",
    "tests.fixtures.bootstrap",
    "tests.fixtures.celery",
    "tests.fixtures.cli",
    "tests.fixtures.communities",
    "tests.fixtures.community_events",
    "tests.fixtures.custom_fields",
    "tests.fixtures.files",
    "tests.fixtures.fixtures",
    "tests.fixtures.frontend",
    "tests.fixtures.identifiers",
    "tests.fixtures.idms",
    "tests.fixtures.indexer_queues",
    "tests.fixtures.logging",
    "tests.fixtures.mail",
    "tests.fixtures.names",
    "tests.fixtures.records",
    "tests.fixtures.roles",
    "tests.fixtures.search",
    "tests.fixtures.search_provisioning",
    # "tests.fixtures.stats",
    "tests.fixtures.uow",
    "tests.fixtures.users",
    "tests.fixtures.vocabularies.affiliations",
    "tests.fixtures.vocabularies.community_types",
    "tests.fixtures.vocabularies.date_types",
    "tests.fixtures.vocabularies.descriptions",
    "tests.fixtures.vocabularies.funding_and_awards",
    "tests.fixtures.vocabularies.languages",
    "tests.fixtures.vocabularies.licenses",
    "tests.fixtures.vocabularies.resource_types",
    "tests.fixtures.vocabularies.roles",
    "tests.fixtures.vocabularies.subjects",
    "tests.fixtures.vocabularies.title_types",
    "tests.pytest_plugins.pytest_live_status",
)


@pytest.fixture(scope="session", autouse=True)
def _patch_rdm_community_inclusion_access_check() -> Generator[None, None, None]:
    """Mirror KCWorks `patch_community_access_restriction_check` for tests.

    Dependency tests use `create_api` without the KCWorks extension; this
    keeps `is_access_restriction_valid` aligned with production for record
    inclusion paths.
    """
    from invenio_rdm_records import requests as rdm_requests

    original = rdm_requests.community_inclusion.is_access_restriction_valid

    def _allow_all(_record, _community) -> bool:
        return True

    rdm_requests.community_inclusion.is_access_restriction_valid = _allow_all
    yield
    rdm_requests.community_inclusion.is_access_restriction_valid = original


@pytest.fixture(scope="session")
def template_loader_paths() -> list[Path]:
    """RUD template directories for the shared `template_loader` fixture.

    Returns:
        list[Path]: Ordered template directories for Jinja.
    """
    package_root = Path(__file__).parent.parent
    return [
        Path(__file__).parent / "helpers" / "templates" / "semantic-ui",
        package_root / "invenio_remote_user_data_kcworks" / "templates" / "semantic-ui",
    ]


@pytest.fixture(scope="module")
def app(app):
    """Wrap shared `app` with the IDMS static-token hook.

    Yields:
        The Flask application instance.
    """
    register_idms_static_api_token_before_request(app)
    yield app


@pytest.fixture(scope="module")
def app_config(app_config) -> dict:
    """Add package-specific keys onto the shared test defaults.

    Uses `IDMS_BASE_API_URL` from the shared urls fragment (already merged
    by `tests.fixtures.app_config`) so endpoint URLs stay aligned with
    whatever the fixtures checkout provides.

    Returns:
        dict: The layered Flask/Invenio application config.
    """
    idms_base = app_config["IDMS_BASE_API_URL"]
    app_config["REMOTE_USER_DATA_API_ENDPOINTS"] = {
        "knowledgeCommons": {
            "title": "Knowledge Commons",
            "users": {
                "remote_endpoint": f"{idms_base}members/",
                "remote_identifier": "id",
                "remote_method": "GET",
                "token_env_variable_label": "COMMONS_PROFILES_API_TOKEN",
            },
            "groups": {
                "remote_endpoint": f"{idms_base}groups/",
                "remote_identifier": "id",
                "remote_method": "GET",
                "token_env_variable_label": "COMMONS_PROFILES_API_TOKEN",
                "group_roles": {
                    "owner": ["administrator"],
                    "curator": ["editor", "moderator"],
                    "reader": ["member"],
                },
            },
            "entity_types": {
                "associations": {"events": ["associated"]},
                "users": {"events": ["created", "updated", "deleted"]},
                "groups": {"events": ["created", "updated", "deleted"]},
            },
        },
    }
    app_config["COMMUNITIES_SERVICE_COMPONENTS"] = [
        BaseCommunityAccessComponent if c is RDMCommunityAccessComponent else c
        for c in CommunityServiceComponents
    ]
    return app_config


@pytest.fixture(scope="module")
def create_app(instance_path, entry_points):
    """Provide the application factory used to build the Flask app.

    Returns `invenio_app.factory.create_api` so that REST API blueprints
    registered under `invenio_base.api_apps` (e.g. the package's webhook
    receiver) are wired into the test app. See the module docstring for
    why this differs from the root KCWorks `conftest.py`.

    Returns:
        Callable: The application factory function.
    """
    return _create_app
