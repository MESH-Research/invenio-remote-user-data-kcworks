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
2. `test_config` keys are set inline rather than loaded from an
   `invenio.cfg` (the root project's config is much larger and full of
   deployment-specific values). The bulk of root's `invenio.cfg` keys
   that can be useful for these tests are listed below as commented
   placeholders so a contributor can flip them on without hunting.

Per the agreed plan, duplicate vocabulary/user/role fixtures previously
defined here were removed in favour of the shared fixture modules vendored
from `kcworks-test-fixtures` (the `tests/fixtures` submodule). One
`COMMUNITIES_SERVICE_COMPONENTS` override remains so API-only tests match
KCWorks community visibility behaviour without loading the full KCWorks
extension.
"""

import os
from collections import namedtuple
from collections.abc import Callable, Generator
from pathlib import Path
from typing import Any

import jinja2
import pytest
from flask import Flask
from invenio_app.factory import create_api as _create_app
from invenio_communities.communities.services.components import (
    CommunityAccessComponent as BaseCommunityAccessComponent,
)
from invenio_queues import current_queues
from invenio_rdm_records.services.communities.components import (
    CommunityAccessComponent as RDMCommunityAccessComponent,
)
from invenio_rdm_records.services.communities.components import (
    CommunityServiceComponents,
)
from marshmallow import Schema, fields

from tests.fixtures.env_defaults import PYTEST_DEFAULT_COMMONS_PROFILES_API_TOKEN
from tests.fixtures.idms import register_idms_static_api_token_before_request

from .fixtures.custom_fields import test_config_fields
from .fixtures.frontend import MockManifestLoader
from .fixtures.identifiers import test_config_identifiers
from .fixtures.logging import log_folder_path, test_config_logging
from .fixtures.names import VOCABULARIES_NAMES_SCHEMES

pytest_plugins = (
    "celery.contrib.pytest",
    # "tests.fixtures.caching",  # depends on invenio-stats-dashboard
    "tests.fixtures.bootstrap",
    "tests.fixtures.cli",
    "tests.fixtures.communities",
    "tests.fixtures.community_events",
    "tests.fixtures.custom_fields",
    "tests.fixtures.files",
    "tests.fixtures.fixtures",
    "tests.fixtures.frontend",
    "tests.fixtures.identifiers",
    "tests.fixtures.idms",
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
def _commons_profiles_api_token_default() -> None:
    """Set a dummy Profiles bearer token when the env omits one.

    `UserDataAPIClient.fetch_user_profile` (and related paths) read
    `COMMONS_PROFILES_API_TOKEN` from the environment. Tests that mock
    IDMS with `requests_mock` still execute that code, so the variable
    must be present.

    Uses `os.environ.setdefault` so an explicit real token set in the
    environment is never overwritten. Live IDMS tests use
    `commons_profiles_api_token_is_live_configured` in `tests/fixtures/env_defaults.py`
    so they still skip when only this placeholder is present.

    Tests that need a specific secret (broker crypto, Authorization header
    assertions, etc.) continue to use `monkeypatch.setenv` per test.
    """
    os.environ.setdefault(
        "COMMONS_PROFILES_API_TOKEN",
        PYTEST_DEFAULT_COMMONS_PROFILES_API_TOKEN,
    )


def _(x: Any) -> Any:
    """Identity function for string extraction.

    Returns:
        Any: The input value unchanged.
    """
    return x


test_config: dict[str, Any] = {
    **test_config_identifiers,
    **test_config_fields,
    **test_config_logging,
    "BABEL_DEFAULT_TIMEZONE": "America/Detroit",
    "VOCABULARIES_NAMES_SCHEMES": VOCABULARIES_NAMES_SCHEMES,
    # --- IDMS ---------------------------------------------------------------
    "IDMS_BASE_API_URL": "https://profile.hcommons-dev.org/api/v1/",
    "KC_REMOTE_IDPS": ["cilogon"],  # "cilogon" *must* be the first value
    "SSO_BROKER_LOGIN_URL": "https://profile.hcommons-dev.org/login/",
    "SSO_BROKER_SILENT_LOGIN_URL": (
        "https://profile.hcommons-dev.org/broker/silent-login/"
    ),
    "SSO_BROKER_VERIFY_NONCE_URL": (
        "https://profile.hcommons-dev.org/broker/verify-nonce/"
    ),
    "SSO_BROKER_RETRY_COOKIE_NAME": "_sso_checked",
    "SSO_BROKER_COOKIE_TTL": 300,
    "SSO_BROKER_SILENT_LOGIN_TIMEOUT": 3,
    # --- Database -----------------------------------------------------------
    "SQLALCHEMY_DATABASE_URI": (
        "postgresql+psycopg2://invenio:invenio@localhost:5432/invenio"
    ),
    "SQLALCHEMY_TRACK_MODIFICATIONS": False,
    # "SQLALCHEMY_POOL_SIZE": None,        # uncomment to disable pooling
    # "SQLALCHEMY_POOL_TIMEOUT": None,
    # --- Search -------------------------------------------------------------
    "SEARCH_INDEX_PREFIX": "",
    # --- Postgres connection (for tooling that reads these directly) -------
    "POSTGRES_USER": "invenio",
    "POSTGRES_PASSWORD": "invenio",
    "POSTGRES_DB": "invenio",
    # --- Web/security -------------------------------------------------------
    "WTF_CSRF_ENABLED": False,
    "WTF_CSRF_METHODS": [],
    "RATELIMIT_ENABLED": False,
    # Static bearer for IDMS→KCWorks API paths (see `tests.fixtures.idms` hook).
    # Tests set `TEST_IDMS_STATIC_API_TOKEN`;
    # `idms_static_api_auth` overrides user id.
    "STATIC_API_TOKEN_ROUTES": {
        "/api/webhooks/user_data_update": "COMMONS_PROFILES_API_TOKEN",
        "/api/webhooks/users/logout": "COMMONS_PROFILES_API_TOKEN",
        "/api/webhooks/users/update": "COMMONS_PROFILES_API_TOKEN",
        "/webhooks/user_data_update": "COMMONS_PROFILES_API_TOKEN",
        "/webhooks/users/logout": "COMMONS_PROFILES_API_TOKEN",
        "/webhooks/users/update": "COMMONS_PROFILES_API_TOKEN",
    },
    "STATIC_API_TOKEN_USER_ID": 1,
    "APP_DEFAULT_SECURE_HEADERS": {
        "content_security_policy": {"default-src": []},
        "force_https": False,
    },
    # --- Queues / Celery ----------------------------------------------------
    "BROKER_URL": "amqp://guest:guest@localhost:5672//",
    "CELERY_TASK_ALWAYS_EAGER": True,
    "CELERY_TASK_EAGER_PROPAGATES_EXCEPTIONS": True,
    "CELERY_LOGLEVEL": "DEBUG",
    "CELERY_CACHE_BACKEND": "memory",
    "CELERY_RESULT_BACKEND": "cache",
    # --- Invenio paths ------------------------------------------------------
    "INVENIO_INSTANCE_PATH": "/opt/invenio/var/instance",
    # --- Mail ---------------------------------------------------------------
    # The package's tests don't actually send mail, but invenio-mail still
    # wants the keys to exist; uncomment if a test needs real configuration.
    "MAIL_SUPPRESS_SEND": True,
    # "MAIL_SERVER": "localhost",
    # "MAIL_PORT": 25,
    # "MAIL_USE_TLS": False,
    # "MAIL_USE_SSL": False,
    # "MAIL_USERNAME": None,
    # "MAIL_PASSWORD": None,
    # "MAIL_DEFAULT_SENDER": "no-reply@example.com",
    "TESTING": True,
    "DEBUG": True,
    # --- Test secrets -------------------------------------------------------
    "SECRET_KEY": "test-secret-key",
    "SECURITY_PASSWORD_SALT": "test-secret-key",
    # --- Webpack / Frontend stub -------------------------------------------
    "WEBPACKEXT_MANIFEST_LOADER": MockManifestLoader,
    # ----------------------------------------------------------------------
    # invenio-remote-user-data-kcworks specific overrides
    # ----------------------------------------------------------------------
    # The package config defaults (see invenio_remote_user_data_kcworks/
    # config.py) are appropriate for tests as-is. Override here if a test
    # case needs different behaviour.
    #
    # "REMOTE_USER_DATA_NAMES_AUTO_MERGE_ON_ORCID": True,
    # "REMOTE_USER_DATA_NAMES_DEDUPE_REPORT_PATH": None,
    # "REMOTE_USER_DATA_ORCID_PROXY_ENABLED": False,
    # "REMOTE_USER_DATA_ORCID_USE_SANDBOX": False,
    # "REMOTE_USER_DATA_ORCID_DAILY_QUOTA": 90_000,
    # "REMOTE_USER_DATA_ORCID_REQUESTS_PER_SECOND": 8,
    # "REMOTE_USER_DATA_API_TIMEOUT": 5,
    # "REMOTE_USER_DATA_UPDATE_INTERVAL": 1,
    # "REMOTE_USER_DATA_USER_CREATED_RESCHEDULE_DELAY": 3600,
    #
}


# -- Users ---------------------------------------------------------------------
class CustomUserProfileSchema(Schema):
    """The default user profile schema."""

    full_name = fields.String()
    affiliations = fields.String()
    name_parts = fields.String()
    name_parts_local = fields.String()
    identifier_email = fields.String()
    identifier_orcid = fields.String()
    identifier_kc_username = fields.String()
    identifier_other = fields.String()
    unread_notifications = fields.String()


test_config["ACCOUNTS_USER_PROFILE_SCHEMA"] = CustomUserProfileSchema()

test_config["ACCOUNTS_DEFAULT_EMAIL_VISIBILITY"] = "public"
test_config["ACCOUNTS_DEFAULT_USER_VISIBILITY"] = "public"

# --- API endpoint configuration -------------------------------------------
test_config["REMOTE_USER_DATA_API_ENDPOINTS"] = {
    "knowledgeCommons": {
        "title": "Knowledge Commons",
        "users": {
            "remote_endpoint": f"{test_config['IDMS_BASE_API_URL']}members/",
            "remote_identifier": "id",
            "remote_method": "GET",
            "token_env_variable_label": "COMMONS_PROFILES_API_TOKEN",
        },
        "groups": {
            "remote_endpoint": f"{test_config['IDMS_BASE_API_URL']}groups/",
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

# --- DataCite (faked) ------------------------------------------------------
test_config["DATACITE_ENABLED"] = True
test_config["DATACITE_USERNAME"] = "INVALID"
test_config["DATACITE_PASSWORD"] = "INVALID"
test_config["DATACITE_DATACENTER_SYMBOL"] = "TEST"
test_config["DATACITE_PREFIX"] = "10.17613"
test_config["DATACITE_TEST_MODE"] = True

# --- Site URLs (env-overridable for cross-environment runs) ----------------
test_config["SITE_API_URL"] = os.environ.get(
    "INVENIO_SITE_API_URL", "http://localhost/api"
)
test_config["SITE_UI_URL"] = os.environ.get("INVENIO_SITE_UI_URL", "http://localhost")

# Match KCWorks `KCWorks.init_components`: replace RDM's
# `CommunityAccessComponent` (blocks restricting visibility when the
# community has public records) with the base Invenio Communities
# component so remote group sync tests behave like production.
test_config["COMMUNITIES_SERVICE_COMPONENTS"] = [
    BaseCommunityAccessComponent if c is RDMCommunityAccessComponent else c
    for c in CommunityServiceComponents
]


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
def celery_config(celery_config) -> dict:
    """Celery app config fixture for invenio-remote-user-data-kcworks.

    NOTE: This doesn't configure individual workers. Just the celery app.

    Returns:
        dict: Celery configuration dictionary.
    """
    celery_config["logfile"] = str(log_folder_path / "celery.log")
    celery_config["loglevel"] = "DEBUG"
    celery_config["task_always_eager"] = True
    celery_config["cache_backend"] = "memory"
    celery_config["result_backend"] = "cache"
    celery_config["task_eager_propagates_exceptions"] = True

    return dict(celery_config)


# Namedtuple aggregating the fixtures most tests need together. Mirrors the
# stats-dashboard `RunningApp` so a developer moving between packages sees
# the same surface.
RunningApp = namedtuple(
    "RunningApp",
    [
        "app",
        "location",
        "cache",
        "create_communities_custom_fields",
        "create_records_custom_fields",
    ],
)


@pytest.fixture(scope="function")
def running_app(
    app,
    location,
    cache,
    create_communities_custom_fields,
    create_records_custom_fields,
) -> RunningApp:
    """Provide an app with the typically needed db data loaded.

    All of these fixtures are often needed together, so collecting them
    under a semantic umbrella makes sense.

    Returns:
        RunningApp: The running application instance fixture.
    """
    return RunningApp(
        app,
        location,
        cache,
        create_communities_custom_fields,
        create_records_custom_fields,
    )


@pytest.fixture(scope="module")
def template_loader() -> Callable:
    """Provide overloaded and custom templates to the test app.

    Returns:
        Callable: A function that loads templates for the test app.
    """

    def load_templates(app):
        """Load templates for the test app."""
        package_root = Path(__file__).parent.parent

        # Package's own templates (if/when the package adds any)
        package_template_path = (
            package_root
            / "invenio_remote_user_data_kcworks"
            / "templates"
            / "semantic-ui"
        )
        # Test stubs that override anything else
        test_template_path = (
            Path(__file__).parent / "helpers" / "templates" / "semantic-ui"
        )

        template_paths: list[str] = []
        candidates: list[str | Path] = [
            test_template_path,
            package_template_path,
        ]
        for path in candidates:
            path_obj = Path(path) if isinstance(path, str) else path
            if path_obj.exists():
                template_paths.append(str(path_obj))

        prev_loader = app.jinja_env.loader  # Invenio_app's themed dispatch loader
        custom_loader = jinja2.ChoiceLoader([
            prev_loader,
            jinja2.FileSystemLoader(template_paths),
        ])
        app.jinja_env.loader = custom_loader

    return load_templates


@pytest.fixture(scope="module")
def app(
    app,
    app_config,
    database,
    search,
    bootstrap_vocabularies,
    template_loader,
    admin_roles,
) -> Generator[Flask, None, None]:
    """Provide an app with the typically needed basic fixtures.

    Use in conjunction with the `running_app` fixture for a complete
    app + db data set. This fixture sets up the basic services (db,
    search, template loader, queues) once per module; `running_app` is
    function-scoped and resets per-test data.

    Yields:
        Flask: The Flask application instance.
    """
    with app.app_context():
        current_queues.declare()
    template_loader(app)
    register_idms_static_api_token_before_request(app)
    yield app


@pytest.fixture(scope="module")
def app_config(app_config) -> dict:
    """Override the `pytest_invenio` app_config with our `test_config`.

    Returns:
        dict: The application configuration dictionary.
    """
    for k, v in test_config.items():
        app_config[k] = v

    return dict(app_config)


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


# --- Package-specific fixtures (genuinely unique to user-data) -------------


@pytest.fixture()
def event_queues(app):
    """Declare and tear down the user-data update message queues.

    The package writes Profiles webhook events onto a Kombu exchange
    declared via `REMOTE_USER_DATA_MQ_EXCHANGE` (see
    `invenio_remote_user_data_kcworks/config.py`). Tests that exercise
    that path need the queues to exist and be empty.
    """
    current_queues.delete()
    try:
        current_queues.declare()
        yield
    finally:
        current_queues.delete()
