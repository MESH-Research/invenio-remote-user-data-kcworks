# -*- coding: utf-8 -*-
#
# Copyright (C) 2023-4 Mesh Research
#
# invenio-remote-user-data is free software; you can redistribute
# it and/or modify it under the terms of the MIT License; see LICENSE file
# for more details.

"""Pytest configuration.

See https://pytest-invenio.readthedocs.io/ for documentation on which test
fixtures are available.
"""
import pytest
from flask_security import login_user
from flask_security.utils import hash_password
from invenio_access.models import ActionRoles, Role
from invenio_access.permissions import superuser_access, system_identity
from invenio_accounts.testutils import login_user_via_session
from invenio_administration.permissions import administration_access_action
from invenio_app.factory import create_app as create_ui_api
from invenio_oauthclient.models import UserIdentity
from invenio_vocabularies.proxies import current_service as vocabulary_service
from invenio_vocabularies.records.api import Vocabulary

import os

# from pprint import pformat

pytest_plugins = ("celery.contrib.pytest",)

AllowAllPermission = type(
    "Allow",
    (),
    {"can": lambda self: True, "allows": lambda *args: True},
)()


def AllowAllPermissionFactory(obj_id, action):
    return AllowAllPermission


def _(x):
    """Identity function for string extraction."""
    return x


@pytest.fixture(scope="module")
def extra_entry_points():
    return {
        "console_scripts": [
            "invenio-remote-user-data = invenio_remote_user_data.cli:cli"
        ],
        "invenio_base.api_apps": [
            "invenio_remote_user_data ="
            " invenio_remote_user_data.ext:InvenioRemoteUserData"
        ],
        "invenio_base.apps": [
            "invenio_remote_user_data ="
            " invenio_remote_user_data.ext:InvenioRemoteUserData"
        ],
        "invenio_base.api_blueprints": [
            "invenio_remote_user_data ="
            " invenio_remote_user_data.views:create_api_blueprint"
        ],
        "invenio_queues.queues": [
            "invenio_remote_user_data ="
            " invenio_remote_user_data.queues:declare_queues"
        ],
        "invenio_celery.tasks": [
            "invenio_remote_user_data = invenio_remote_user_data.tasks"
        ],
    }


# @pytest.fixture(scope="module")
# def celery_config():
#     """Override pytest-invenio fixture.

#     TODO: Remove this fixture if you add Celery support.
#     """
#     return {}


test_config = {
    "SQLALCHEMY_DATABASE_URI": (
        "postgresql+psycopg2://"
        "knowledge-commons-repository:"
        "knowledge-commons-repository@localhost/"
        "knowledge-commons-repository-test"
    ),
    "SQLALCHEMY_TRACK_MODIFICATIONS": True,
    "SQLALCHEMY_POOL_SIZE": None,
    "SQLALCHEMY_POOL_TIMEOUT": None,
    "FILES_REST_DEFAULT_STORAGE_CLASS": "L",
    "INVENIO_WTF_CSRF_ENABLED": False,
    "INVENIO_WTF_CSRF_METHODS": [],
    "APP_DEFAULT_SECURE_HEADERS": {
        "content_security_policy": {"default-src": []},
        "force_https": False,
    },
    "BROKER_URL": "amqp://guest:guest@localhost:5672//",
    "CELERY_CACHE_BACKEND": "memory",
    "CELERY_RESULT_BACKEND": "cache",
    "CELERY_TASK_ALWAYS_EAGER": True,
    "CELERY_TASK_EAGER_PROPAGATES_EXCEPTIONS": True,
    "RATELIMIT_ENABLED": False,
    "SECRET_KEY": "test-secret-key",
    "SECURITY_PASSWORD_SALT": "test-secret-key",
    "TESTING": True,
    "CELERY_CACHE_BACKEND": "memory",
    "CELERY_RESULT_BACKEND": "cache",
    "CELERY_TASK_ALWAYS_EAGER": True,
    "CELERY_TASK_EAGER_PROPAGATES_EXCEPTIONS": True,
    "RATELIMIT_ENABLED": False,
    "SECRET_KEY": "test-secret-key",
    "SECURITY_PASSWORD_SALT": "test-secret-key",
    "TESTING": True,
}

SITE_UI_URL = os.environ.get("INVENIO_SITE_UI_URL", "http://localhost:5000")


# Vocabularies


@pytest.fixture(scope="module")
def resource_type_type(app):
    """Resource type vocabulary type."""
    return vocabulary_service.create_type(
        system_identity, "resourcetypes", "rsrct"
    )


@pytest.fixture(scope="module")
def resource_type_v(app, resource_type_type):
    """Resource type vocabulary record."""
    vocabulary_service.create(
        system_identity,
        {
            "id": "dataset",
            "icon": "table",
            "props": {
                "csl": "dataset",
                "datacite_general": "Dataset",
                "datacite_type": "",
                "openaire_resourceType": "21",
                "openaire_type": "dataset",
                "eurepo": "info:eu-repo/semantics/other",
                "schema.org": "https://schema.org/Dataset",
                "subtype": "",
                "type": "dataset",
            },
            "title": {"en": "Dataset"},
            "tags": ["depositable", "linkable"],
            "type": "resourcetypes",
        },
    )

    vocabulary_service.create(
        system_identity,
        {  # create base resource type
            "id": "image",
            "props": {
                "csl": "figure",
                "datacite_general": "Image",
                "datacite_type": "",
                "openaire_resourceType": "25",
                "openaire_type": "dataset",
                "eurepo": "info:eu-repo/semantic/other",
                "schema.org": "https://schema.org/ImageObject",
                "subtype": "",
                "type": "image",
            },
            "icon": "chart bar outline",
            "title": {"en": "Image"},
            "tags": ["depositable", "linkable"],
            "type": "resourcetypes",
        },
    )

    vocab = vocabulary_service.create(
        system_identity,
        {
            "id": "image-photograph",
            "props": {
                "csl": "graphic",
                "datacite_general": "Image",
                "datacite_type": "Photo",
                "openaire_resourceType": "25",
                "openaire_type": "dataset",
                "eurepo": "info:eu-repo/semantic/other",
                "schema.org": "https://schema.org/Photograph",
                "subtype": "image-photograph",
                "type": "image",
            },
            "icon": "chart bar outline",
            "title": {"en": "Photo"},
            "tags": ["depositable", "linkable"],
            "type": "resourcetypes",
        },
    )

    Vocabulary.index.refresh()

    return vocab


# Basic app fixtures


@pytest.fixture(scope="module")
def app_config(app_config) -> dict:
    for k, v in test_config.items():
        app_config[k] = v
    return app_config


@pytest.fixture(scope="module")
def create_app(entry_points):
    return create_ui_api


@pytest.fixture(scope="module")
def testapp(app):
    """Application database and search."""
    yield app


@pytest.fixture()
def user_factory(app, db):
    def make_user(
        email="info@inveniosoftware.org", password="password", **kwargs
    ):
        with db.session.begin_nested():
            datastore = app.extensions["security"].datastore
            user1 = datastore.create_user(
                email=email,
                password=hash_password(password),
                active=True,
            )
        db.session.commit()
        return user1

    return make_user


@pytest.fixture()
def user_factory_logged_in(app, db, user_factory):
    def client_with_login(
        client, email="info@inveniosoftware.org", password="password", **kwargs
    ):
        """Log in a user to the client."""
        user = user_factory(email, password)
        login_user(user)
        login_user_via_session(client, email=user.email)
        return client

    return client_with_login


@pytest.fixture()
def myuser(UserFixture, testapp, db):
    u = UserFixture(
        email="myuser@inveniosoftware.org",
        password="auser",
    )
    u.create(testapp, db)
    u.roles = u.user.roles
    return u


@pytest.fixture()
def myuser2(UserFixture, testapp, db):
    u = UserFixture(
        email="myuser2@inveniosoftware.org",
        password="auser2",
    )
    u.create(testapp, db)
    u.roles = u.user.roles
    return u


@pytest.fixture()
def minimal_record():
    """Minimal record data as dict coming from the external world."""
    return {
        "pids": {},
        "access": {
            "record": "public",
            "files": "public",
        },
        "files": {
            "enabled": False,  # Most tests don't care about files
        },
        "metadata": {
            "creators": [
                {
                    "person_or_org": {
                        "family_name": "Brown",
                        "given_name": "Troy",
                        "type": "personal",
                    }
                },
                {
                    "person_or_org": {
                        "name": "Troy Inc.",
                        "type": "organizational",
                    },
                },
            ],
            "publication_date": "2020-06-01",
            # because DATACITE_ENABLED is True, this field is required
            "publisher": "Acme Inc",
            "resource_type": {"id": "image-photograph"},
            "title": "A Romans story",
        },
    }


@pytest.fixture()
def admin_role_need(db):
    """Store 1 role with 'superuser-access' ActionNeed.

    WHY: This is needed because expansion of ActionNeed is
         done on the basis of a User/Role being associated with that Need.
         If no User/Role is associated with that Need (in the DB), the
         permission is expanded to an empty list.
    """
    role = Role(name="administration-access")
    db.session.add(role)

    action_role = ActionRoles.create(
        action=administration_access_action, role=role
    )
    db.session.add(action_role)

    db.session.commit()

    return action_role.need


@pytest.fixture()
def admin(UserFixture, app, db, admin_role_need):
    """Admin user for requests."""
    u = UserFixture(
        email="admin@inveniosoftware.org",
        password="admin",
    )
    u.create(app, db)

    datastore = app.extensions["security"].datastore
    _, role = datastore._prepare_role_modify_args(
        u.user, "administration-access"
    )

    UserIdentity.create(u.user, "knowledgeCommons", "myuser")

    datastore.add_role_to_user(u.user, role)
    db.session.commit()
    return u


@pytest.fixture()
def superuser_role_need(db):
    """Store 1 role with 'superuser-access' ActionNeed.

    WHY: This is needed because expansion of ActionNeed is
         done on the basis of a User/Role being associated with that Need.
         If no User/Role is associated with that Need (in the DB), the
         permission is expanded to an empty list.
    """
    role = Role(name="superuser-access")
    db.session.add(role)

    action_role = ActionRoles.create(action=superuser_access, role=role)
    db.session.add(action_role)

    db.session.commit()

    return action_role.need


@pytest.fixture()
def delete_role_need(db):
    """Store 1 role with 'delete' ActionNeed.

    WHY: This is needed because expansion of ActionNeed is
         done on the basis of a User/Role being associated with that Need.
         If no User/Role is associated with that Need (in the DB), the
         permission is expanded to an empty list.
    """
    role = Role(name="delete")
    db.session.add(role)

    action_role = ActionRoles.create(action=superuser_access, role=role)
    db.session.add(action_role)

    db.session.commit()

    return action_role.need


@pytest.fixture()
def superuser_identity(admin, superuser_role_need, delete_role_need):
    """Superuser identity fixture."""
    identity = admin.identity
    identity.provides.add(superuser_role_need)
    identity.provides.add(delete_role_need)
    return identity
