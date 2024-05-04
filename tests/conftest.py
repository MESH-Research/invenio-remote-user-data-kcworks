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
from invenio_communities.proxies import current_communities
from invenio_oauthclient.models import UserIdentity
from invenio_records_resources.services.custom_fields import TextCF
from invenio_records_resources.services.custom_fields.errors import (
    CustomFieldsException,
)
from invenio_records_resources.services.custom_fields.mappings import Mapping
from invenio_records_resources.services.custom_fields.validate import (
    validate_custom_fields,
)
from invenio_search import current_search_client
from invenio_search.engine import dsl
from invenio_search.engine import search as search_engine
from invenio_search.utils import build_alias_name
from invenio_vocabularies.proxies import current_service as vocabulary_service
from invenio_vocabularies.records.api import Vocabulary

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
    # "THEME_FRONTPAGE_TEMPLATE": "invenio_remote_user_data/base.html",
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
            "Can manage members, curate records "
            "and view restricted records."
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
        "description": (
            "Information about a Commons group that owns the collection"
        ),
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


test_config["SSO_SAML_IDPS"] = {
    # name your authentication provider
    "knowledgeCommons": {
        # Basic info
        "title": "Knowledge Commons",
        "description": "Knowledge Commons Authentication Service",
        # "icon": "",
        # path to the file i.e. "./saml/sp.crt"
        "sp_cert_file": "./docker/nginx/samlCertificate.crt",
        # path to the file i.e. "./saml/sp.key"
        "sp_key_file": "./docker/nginx/samlPrivateKey.key",
        "settings": {
            # If strict is True, then the Python Toolkit will reject unsigned
            # or unencrypted messages if it expects them to be signed
            # or encrypted.
            # Also it will reject the messages if the SAML standard is
            # not strictly
            # followed. Destination, NameId, Conditions ... are validated too.
            "strict": False,
            # Enable debug mode (outputs errors).
            # TODO: change before production
            "debug": True,
            # Service Provider Data that we are deploying.
            "sp": {
                # NOTE: Assertion consumer service is https://localhost/saml/
                # authorized/knowledgeCommons
                # NOTE: entityId for the dev SP is
                # https://localhost/saml/metadata/knowledgeCommons
                # NOTE: entityId for the staging SP is
                # https://invenio-dev.hcommons-staging.org/saml/idp
                # Specifies the constraints on the name identifier to be used
                # to represent the requested subject.
                # Take a look on https://github.com/onelogin/python-saml/
                # blob/master/src/onelogin/saml2/constants.py
                # to see the NameIdFormat that are supported.
                "NameIDFormat": (
                    "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
                ),
            },
            # Identity Provider Data that we want connected with our SP.
            "idp": {
                # Identifier of the IdP entity  (must be a URI)
                "entityId": "https://proxy.hcommons-dev.org/idp",
                # SSO endpoint info of the IdP. (Authentication
                # Request protocol)
                "singleSignOnService": {
                    # URL Target of the IdP where the Authentication
                    # Request Message will be sent.
                    "url": "https://proxy.hcommons-dev.org/Saml2/sso/redirect",
                    # SAML protocol binding to be used when returning the
                    # <Response> message. OneLogin Toolkit supports
                    # the HTTP-Redirect binding
                    # only for this endpoint.
                    "binding": (
                        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                    ),
                },
                # SLO endpoint info of the IdP.
                "singleLogoutService": {
                    # URL Location where the <LogoutRequest> from the IdP
                    # will be sent (IdP-initiated logout)
                    "url": "https://localhost/saml/slo/knowledgeCommons",
                    # SAML protocol binding to be used when returning
                    # the <Response> message. OneLogin Toolkit supports
                    # the HTTP-Redirect binding
                    # only for this endpoint.
                    "binding": (
                        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                    ),
                },
                # Public X.509 certificate of the IdP
                "x509cert": (
                    "MIIELTCCApWgAwIBAgIJAPeDxhrttBXNMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNVBAMTFnByb3h5Lmhjb21tb25zLWRldi5vcmcwHhcNMTcxMTAxMTc0NTE3WhcNMjcxMDMwMTc0NTE3WjAhMR8wHQYDVQQDExZwcm94eS5oY29tbW9ucy1kZXYub3JnMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA0d6ycqcxviv946IzS7ZobCK0XAsrwHvcKo65hWkOZsxYBTRvjKITSpKv4TGyVG4leI0Ifthz7o3QAA4IKkkgY15kYO5AhJc9pVa+11vG0DM58qO6yraQRM4U/71AgDEmEZXsUblf3TCkN5w351G26jNwgax+aWNuwzX5EDS5farOhruGG2FwVYEOEHOtWSOKBR8duq1O/yY9OKMhIc2kmh9R"  # noqa: E501
                    " m1594qTzZbxNXjyCY+LU/GZbYQP+WlbjM/dHflK5Y2WexyT942xHYnesvPnzGvEMB4g685Yyjl+9xz+AE41sifKYy03m7GgkimXNxQ2SnGZ4Rtj+3DlDC9S/dB2CRJd2uaTwgxEEK/zJJ1K2TFRfDH/wxCW5DwI3n8BMglc8TPZ33FDqNgZPwPDl92/shwNIU3sFM/lmDtLm/4XeKZjOZYa+WCVC71tnFYDltK1//oAqFSVRF0WT6+dcnjXxJSdRrQo+C1gWI+aXJzmDmhp8WBN2q7nUGapJYSu0a5yXAgMBAAGjaDBmMEUGA1UdEQQ+MDyCFnByb3h5Lmhjb21tb25zLWRldi5vcmeGImh0dHBzOi8vcHJveHkuaGNvbW1vbnMtZGV2Lm9yZy9pZHAwHQYDVR0OBBYEFDLkys52MyePCpr5IN2ybhgIosmlMA0GCSqGSIb3DQEBCwUAA4IBgQDOuUnSwfru5uNorAISo5QEVUi3UrholF0RPFFvM6P63MOpWZwdFQYKjY1eaaE+X++AZ1FkHQv/esy7F0FRWiyU3LHUX3Yzuttb7vj7mw5D6IYuSIG1/0Edj/eSpnOs+6MQUUpfaFi+A0C9Smng6L1kj3SOlePprJdwfIdGG/6oiDaF1bhoWs/eidouzMLMKiGY6KzmaT8fInST1BGMdm4+zqNvwd1FuifDOvVQqqtl"  # noqa: E501
                    " q2og0arTXG01YyCvU+NJT/6KjLDZf1bSmDWAPQ51Fc4fpkeOj+aG0DfwdutO2SNkdDDdD/m7pnepxv2u8jqSKyYKdrzLd0lJPrqH8YV4AYmyJ1UortJXFoTsGSbPv0fw"  # noqa: E501
                    " qM1b1JAKsPMP22xmp2i4BcYOT1jZ+R+RXmMNK+fUSXAmSkhk/8h6CMgmU4ldBj5jtyn/M4GrGesMU1sIgidoCj/5F3jQlswz0eoaX3LyWQkDZbUbIm6Vz4h3GFwwlky8c5RbLEmwlolP+zSzoq4T/tw="  # noqa: E501
                ),
            },
            # Security settings
            # more on https://github.com/onelogin/python-saml
            "security": {
                "authnRequestsSigned": False,
                "failOnAuthnContextMismatch": False,
                "logoutRequestSigned": False,
                "logoutResponseSigned": False,
                "metadataCacheDuration": None,
                "metadataValidUntil": None,
                "nameIdEncrypted": False,
                "requestedAuthnContext": False,
                "requestedAuthnContextComparison": "exact",
                "signMetadata": False,
                "signatureAlgorithm": (
                    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
                ),
                "wantAssertionsEncrypted": False,
                "wantAssertionsSigned": False,
                "wantAttributeStatement": False,
                "wantMessagesSigned": False,
                "wantNameId": True,
                "wantNameIdEncrypted": False,
                "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
            },
        },
        # Account Mapping
        "mappings": {
            "email": "urn:oid:0.9.2342.19200300.100.1.3",  # "mail"
            # "name": "urn:oid:2.5.4.3",  # "cn"
            "name": "urn:oid:2.5.4.42",  # "givenName"
            "surname": "urn:oid:2.5.4.4",  # "sn"
            "external_id": (
                "urn:oid:2.16.840.1.113730.3.1.3"
            ),  # "employeeNumber"
        },  # FIXME: new entity id url, assertion consumer service url,
        # certificate
        # "title", 'urn:oid:2.5.4.12': ['Hc Developer'],
        # 'urn:oid:2.16.840.1.113730.3.1.3': ['iscott'],
        # 'urn:oid:0.9.2342.19200300.100.1.1':
        #   ['100103028069838784737+google.com@commons.mla.org'],
        # "isMemberOf", 'urn:oid:1.3.6.1.4.1.5923.1.5.1.1':
        #   ['CO:COU:HC:members:active'],
        # 'urn:oid:1.3.6.1.4.1.49574.110.13':
        #   ['https://google-gateway.hcommons-dev.org/idp/shibboleth'],
        # 'urn:oid:1.3.6.1.4.1.49574.110.10': ['Google login'],
        # 'urn:oid:1.3.6.1.4.1.49574.110.11': ['Humanities Commons'],
        # 'urn:oid:1.3.6.1.4.1.49574.110.12': ['Humanities Commons']}
        # Inject your remote_app to handler
        # Note: keep in mind the string should match
        # given name for authentication provider
        # NOTE: commented out to avoid import:
        # "acs_handler": acs_handler_factory("knowledgeCommons"),
        # Automatically set `confirmed_at` for users upon
        # registration, when using the default `acs_handler`
        "auto_confirm": True,
    }
}


class CustomAffiliationSchema(Schema):
    """The default affiliations schema."""

    name = fields.String()
    id = fields.String()


class CustomNamePartsSchema(Schema):
    """The default name parts schema."""

    first = fields.String()
    middle = fields.String()
    last = fields.String()
    last_prefix_for_alphabetizing = fields.String()
    last_prefix = fields.String()
    patronymic = fields.String()
    undivided = fields.String()


class CustomUserIdentifierSchema(Schema):
    """The default user identifier schema."""

    identifier = fields.String()
    scheme = fields.String()


class CustomUserProfileSchema(Schema):
    """The default user profile schema."""

    full_name = fields.String()
    # affiliations = fields.List(fields.Nested(CustomAffiliationSchema))
    affiliations = fields.String()
    name_parts = fields.Nested(CustomNamePartsSchema)
    identifiers = fields.List(fields.Nested(CustomUserIdentifierSchema))


test_config["ACCOUNTS_USER_PROFILE_SCHEMA"] = CustomUserProfileSchema

test_config["REMOTE_USER_DATA_API_ENDPOINTS"] = {
    "knowledgeCommons": {
        "users": {
            "remote_endpoint": (
                "https://hcommons-dev.org/wp-json/commons/v1/users/"
            ),
            "remote_identifier": "id",
            "remote_method": "GET",
            "token_env_variable_label": "COMMONS_API_TOKEN",
        },
        "groups": {
            "remote_endpoint": (
                "https://hcommons-dev.org/wp-json/commons/v1/groups/"
            ),
            "remote_identifier": "id",
            "remote_method": "GET",
            "token_env_variable_label": "COMMONS_API_TOKEN",
        },
        "entity_types": {
            "users": {"events": ["created", "updated", "deleted"]},
            "groups": {"events": ["created", "updated", "deleted"]},
        },
    }
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
def custom_fields(app):
    create_communities_custom_fields(app)
    return True


@pytest.fixture(scope="module")
def testapp(app):
    """Application database and search."""
    yield app


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
            build_alias_name(
                current_communities.service.config.record_cls.index._name
            ),
            using=current_search_client,
        )
        communities_index.put_mapping(body={"properties": properties})
    except search_engine.RequestError as e:
        print("An error occured while creating custom fields.")
        print(e.info["error"]["reason"])


@pytest.fixture(scope="function")
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
                **kwargs,
            )
        db.session.commit()
        return user1

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
def myuser(UserFixture, testapp, db):
    u = UserFixture(
        email="auser@inveniosoftware.org",
        password="auser",
    )
    u.create(testapp, db)
    u.roles = u.user.roles
    return u


@pytest.fixture(scope="function")
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
    """Store 1 role with 'administration-access' ActionNeed.

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
