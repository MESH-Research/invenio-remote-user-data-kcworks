# -*- coding: utf-8 -*-
#
# Copyright (C) 2023-4 Mesh Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute
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
from invenio_app.factory import create_api  # create_app as create_ui_api
from invenio_communities.proxies import (
    current_communities,
)
from invenio_oauthclient.models import UserIdentity
from invenio_oauth2server.models import Token
from invenio_queues.proxies import current_queues
from invenio_records_resources.services.custom_fields import (
    TextCF,
)
from invenio_records_resources.services.custom_fields.errors import (
    CustomFieldsException,
)
from invenio_records_resources.services.custom_fields.mappings import (
    Mapping,
)
from invenio_records_resources.services.custom_fields.validate import (
    validate_custom_fields,
)
from invenio_search import current_search_client
from invenio_search.engine import dsl
from invenio_search.engine import search as search_engine
from invenio_search.utils import build_alias_name
from invenio_vocabularies.proxies import current_service as vocabulary_service
from invenio_vocabularies.records.api import Vocabulary
from kombu import Exchange

from marshmallow import Schema, fields
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


test_config = {
    # "THEME_FRONTPAGE_TEMPLATE": "invenio_remote_user_data_kcworks/base.html",
    "SQLALCHEMY_DATABASE_URI": (
        "postgresql+psycopg2://invenio:invenio@localhost/invenio"
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
    "QUEUES_BROKER_URL": "amqp://guest:guest@localhost:5672//",
    "REMOTE_USER_DATA_MQ_EXCHANGE": Exchange(
        "user-data-updates",
        type="direct",
        delivery_mode="transient",  # in-memory queue
        durable=True,
    ),
    "CELERY_CACHE_BACKEND": "memory",
    "CELERY_RESULT_BACKEND": "cache",
    "CELERY_TASK_ALWAYS_EAGER": True,
    "CELERY_TASK_EAGER_PROPAGATES_EXCEPTIONS": True,
    "RATELIMIT_ENABLED": False,
    "SECRET_KEY": "test-secret-key",
    "SECURITY_PASSWORD_SALT": "test-secret-key",
    "TESTING": True,
}

test_config["COMMUNITIES_ROLES"] = [
    dict(
        name="reader",
        title=_("Reader"),
        description=_("Can view restricted records."),
        can_view=True,
    ),
    dict(
        name="curator",
        title=_("Curator"),
        description=_("Can curate records and view restricted records."),
        can_curate=True,
        can_view=True,
    ),
    dict(
        name="manager",
        title=_("Manager"),
        description=_(
            "Can manage members, curate records and view restricted records."
        ),
        can_manage_roles=["manager", "curator", "reader"],
        can_manage=True,
        can_curate=True,
        can_view=True,
    ),
    # dict(
    #     name="administrator",
    #     title=_("Administrator"),
    #     description=_("Full administrative access to the entire community."),
    #     can_manage_roles=["administrator", "manager", "curator", "reader"],
    #     can_manage=True,
    #     can_curate=True,
    #     can_view=True,
    # ),
    dict(
        name="owner",
        title=_("Owner"),
        description=_("Full administrative access to the entire community."),
        can_manage_roles=[
            "owner",
            "administrator",
            "manager",
            "curator",
            "reader",
        ],
        can_manage=True,
        can_curate=True,
        can_view=True,
        is_owner=True,
    ),
]
"""Community roles."""

test_config["COMMUNITIES_NAMESPACES"] = {
    "kcr": "https://invenio-dev.hcommons-staging.org/terms/"
}

test_config["COMMUNITIES_CUSTOM_FIELDS"] = [
    TextCF(name="kcr:commons_instance"),
    TextCF(name="kcr:commons_group_id"),
    TextCF(name="kcr:commons_group_name"),
    TextCF(name="kcr:commons_group_description"),
    TextCF(name="kcr:commons_group_visibility"),
]

test_config["COMMUNITIES_CUSTOM_FIELDS_UI"] = [
    {
        "section": "Linked Commons Group",
        "hidden": False,
        "description": ("Information about a Commons group that owns the collection"),
        "fields": [
            {
                "field": "kcr:commons_group_name",
                "ui_widget": "Input",
                "props": {
                    "label": "Commons Group Name",
                    "placeholder": "",
                    "icon": "",
                    "description": ("Name of the Commons group."),
                    "disabled": True,
                },
            },
            {
                "field": "kcr:commons_group_id",
                "ui_widget": "Input",
                "props": {
                    "label": "Commons Group ID",
                    "placeholder": "",
                    "icon": "",
                    "description": ("ID of the Commons group"),
                    "disabled": True,
                },
            },
            {
                "field": "kcr:commons_instance",
                "ui_widget": "Input",
                "props": {
                    "label": "Commons Instance",
                    "placeholder": "",
                    "icon": "",
                    "description": (
                        "The Commons to which the group belongs (e.g., "
                        "STEMEd+ Commons, MLA Commons, Humanities Commons)"
                    ),
                    "disabled": True,
                },
            },
            {
                "field": "kcr:commons_group_description",
                "ui_widget": "Input",
                "props": {
                    "label": "Commons Group Description",
                    "placeholder": "",
                    "icon": "",
                    "description": ("Description of the Commons group."),
                    "disabled": True,
                },
            },
            {
                "field": "kcr:commons_group_visibility",
                "ui_widget": "Input",
                "props": {
                    "label": "Commons Group Visibility",
                    "placeholder": "",
                    "icon": "",
                    "description": ("Visibility of the Commons group."),
                    "disabled": True,
                },
            },
        ],
    }
]


SITE_UI_URL = os.environ.get("INVENIO_SITE_UI_URL", "http://localhost:5000")


# Vocabularies


@pytest.fixture(scope="module")
def resource_type_type(app):
    """Resource type vocabulary type."""
    return vocabulary_service.create_type(system_identity, "resourcetypes", "rsrct")


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
    return create_api


@pytest.fixture()
def event_queues(app):
    """Delete and declare test queues."""
    current_queues.delete()
    try:
        current_queues.declare()
        yield
    finally:
        current_queues.delete()


@pytest.fixture(scope="function")
def db_session_options():
    """Database session options.

    Use to override options like ``expire_on_commit`` for the database session, which
    helps with ``sqlalchemy.orm.exc.DetachedInstanceError`` when models are not bound
    to the session between transactions/requests/service-calls.

    .. code-block:: python

        @pytest.fixture(scope='function')
        def db_session_options():
            return dict(expire_on_commit=False)
    """
    return {"expire_on_commit": False}


@pytest.fixture(scope="function")
def custom_fields(app):
    create_communities_custom_fields(app)
    return True


def create_communities_custom_fields(app):
    """Creates one or all custom fields for communities.

    $ invenio custom-fields communities create [field].
    """
    available_fields = app.config.get("COMMUNITIES_CUSTOM_FIELDS")
    namespaces = set(app.config.get("COMMUNITIES_NAMESPACES").keys())
    try:
        validate_custom_fields(
            given_fields=None,
            available_fields=available_fields,
            namespaces=namespaces,
        )
    except CustomFieldsException as e:
        print(f"Custom fields configuration is not valid. {e.description}")
    # multiple=True makes it an iterable
    properties = Mapping.properties_for_fields(None, available_fields)

    try:
        communities_index = dsl.Index(
            build_alias_name(current_communities.service.config.record_cls.index._name),
            using=current_search_client,
        )
        communities_index.put_mapping(body={"properties": properties})
        communities_index.refresh()

    except search_engine.RequestError as e:
        print("An error occured while creating custom fields.")
        print(e.info["error"]["reason"])


@pytest.fixture(scope="function")
def user_factory(app, db, UserFixture):
    def make_user(email="info@inveniosoftware.org", password="password", **kwargs):
        # with db.session.begin_nested():
        #     datastore = app.extensions["security"].datastore
        #     user1 = datastore.create_user(
        #         email=email,
        #         password=hash_password(password),
        #         active=True,
        #         **kwargs,
        #     )
        # db.session.commit()
        u = UserFixture(
            email=email,
            password=password,
        )
        u.create(app, db)

        return u.user

    return make_user


@pytest.fixture(scope="function")
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


@pytest.fixture(scope="function")
def myuser(UserFixture, app, db):
    u = UserFixture(
        email="auser@inveniosoftware.org",
        password="auser",
    )
    u.create(app, db)
    u.roles = u.user.roles
    return u


@pytest.fixture(scope="function")
def myuser2(UserFixture, app, db):
    u = UserFixture(
        email="myuser2@inveniosoftware.org",
        password="auser2",
    )
    u.create(app, db)
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
    """Store 1 role with 'administration-access' ActionNeed.

    WHY: This is needed because expansion of ActionNeed is
         done on the basis of a User/Role being associated with that Need.
         If no User/Role is associated with that Need (in the DB), the
         permission is expanded to an empty list.
    """
    role = Role(name="administration-access")
    db.session.add(role)

    action_role = ActionRoles.create(action=administration_access_action, role=role)
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

    u.allowed_token = Token.create_personal(
        "webhook",
        u.id,
        scopes=[],  # , is_internal=False
    ).access_token

    db.session.commit()

    datastore = app.extensions["security"].datastore
    _, role = datastore._prepare_role_modify_args(u.user, "administration-access")

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
