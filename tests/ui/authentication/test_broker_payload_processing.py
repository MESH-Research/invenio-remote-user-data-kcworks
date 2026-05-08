# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""Test authentication broker response processing for invenio-remote-user-data-kcworks.

Focuses on processing of response payloads from the Profiles auth broker (token and
nonce).

These tests aim to be as lightweight as possible and so *do not* pull in the search
index fixture. A full live workflow test is included in the UI integration test module.
"""

import os
import secrets
import time
from unittest.mock import MagicMock

import pytest
from invenio_accounts.models import UserIdentity
from invenio_accounts.proxies import current_datastore

from invenio_remote_user_data_kcworks.errors import (
    BrokerNonceValidationError,
    BrokerPayloadExpiredError,
    BrokerTokenDecryptionError,
)
from invenio_remote_user_data_kcworks.utils.broker import SecureParamEncoder
from tests.fixtures.idms import IDMS_SUBS_RESPONSE_SUB
from tests.fixtures.names import SAMPLE_NAME_RESULT


def test_return_handler_new_user(base_app, db, client, requests_mock, monkeypatch):
    """Test that the sso return handler behaves correctly.

    1. Decodes token
    2. Validates nonce
    3. Creates a new user for the missing one
    4. Redirects correctly to the final return path.
    """
    app = base_app
    monkeypatch.setenv("COMMONS_PROFILES_API_TOKEN", secrets.token_urlsafe(32))
    mock_final_redirect = f"{base_app.config.get('SITE_UI_URL')}/search"

    secret = os.getenv("COMMONS_PROFILES_API_TOKEN")
    token_payload = {
        "userinfo": {
            "sub": "http://cilogon.org/serverE/users/XXXXXX",
            "email": "gihctester@gmail.com",
            "name": "Ghost Hc",
            "idp_name": "Gmail",
        },
        "final_redirect": mock_final_redirect,
        "kc_username": "gihctester",
        "primary_email": "gihctester@gmail.com",
        "nonce": "test-nonce",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    mock_broker_token = SecureParamEncoder(secret).encode(token_payload)

    user_api_url = app.config.get("IDMS_BASE_API_URL")
    user_api_adapter = requests_mock.get(
        f"{user_api_url}subs/?sub=http://cilogon.org/serverE/users/XXXXXX",
        json=IDMS_SUBS_RESPONSE_SUB,
    )

    nonce_api_adapter = requests_mock.post(
        app.config.get("SSO_BROKER_VERIFY_NONCE_URL"), json={"valid": True}
    )

    mock_names_task = MagicMock(name="sync_user_to_names")
    mock_names_task.return_value = SAMPLE_NAME_RESULT
    monkeypatch.setattr(
        "invenio_remote_user_data_kcworks.utils.broker.sync_user_to_names",
        mock_names_task,
    )
    monkeypatch.setattr(
        "invenio_remote_user_data_kcworks.tasks.sync_user_to_names",
        mock_names_task,
    )

    response = client.get(
        "/sso/broker-callback/",
        query_string={
            "broker_token": mock_broker_token,
            "final_redirect": mock_final_redirect,
        },
    )

    # nonce validation happened
    assert nonce_api_adapter.called
    assert nonce_api_adapter.call_count == 1
    assert nonce_api_adapter.last_request.method == "POST"
    assert nonce_api_adapter.last_request.json() == {"nonce": "test-nonce"}

    # user data api sync happened
    assert user_api_adapter.called
    assert user_api_adapter.call_count == 1

    # user is redirected to correct url
    assert response.status_code == 302
    assert response.headers["Location"] == mock_final_redirect

    # user was created automatically
    new_user = current_datastore.get_user_by_email(token_payload["userinfo"]["email"])
    assert (
        new_user.user_profile.get("identifier_kc_username")
        == token_payload["kc_username"]
    )
    assert new_user.user_profile.get("name_parts") == '{"first": "Ghost", "last": "Hc"}'

    assert mock_names_task.delay.called
    assert mock_names_task.delay.call_count == 1


def test_return_handler_existing_user(
    base_app,
    db,
    client,
    user_factory,
    UserFixture,
    requests_mock,
    monkeypatch,
):
    """Test that the sso return handler behaves correctly.

    NOTE: This test finds the user based on sub id and UserIdentity table. This is
      the most common case, since we always have a sub in the broker response token
      and *should* always have a UserIdentity for existing users.

    1. Decodes token
    2. Validates nonce
    3. Updates user data
    4. Redirects correctly to the final return path.
    """
    app = base_app
    monkeypatch.setenv("COMMONS_PROFILES_API_TOKEN", secrets.token_urlsafe(32))
    mock_final_redirect = f"{app.config.get('SITE_UI_URL')}/search"

    cilogon_sub = "http://cilogon.org/serverE/users/XXXXXX"
    existing_user = user_factory(
        email="gihctester@gmail.com",
        password="password",
        oauth_id=cilogon_sub,
    )
    # Ensure prior identity association was made
    assert UserIdentity.query.filter_by(
        id_user=existing_user.user.id, id=cilogon_sub, method="cilogon"
    ).one_or_none()

    secret = os.getenv("COMMONS_PROFILES_API_TOKEN")
    token_payload = {
        "userinfo": {
            "sub": cilogon_sub,
            "email": "gihctester@gmail.com",
            "name": "Ghost Hc",
            "idp_name": "Gmail",
        },
        "final_redirect": mock_final_redirect,
        "kc_username": "gihctester",
        "orcid": "0000-0002-1825-0097",
        "primary_email": "gihctester@gmail.com",
        "nonce": "test-nonce",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    mock_broker_token = SecureParamEncoder(secret).encode(token_payload)

    user_api_url = app.config.get("IDMS_BASE_API_URL")
    user_api_adapter = requests_mock.get(
        f"{user_api_url}subs/?sub={cilogon_sub}",
        json=IDMS_SUBS_RESPONSE_SUB,
    )

    nonce_api_adapter = requests_mock.post(
        app.config.get("SSO_BROKER_VERIFY_NONCE_URL"), json={"valid": True}
    )

    mock_names_task = MagicMock(name="sync_user_to_names")
    mock_names_task.return_value = SAMPLE_NAME_RESULT
    monkeypatch.setattr(
        "invenio_remote_user_data_kcworks.utils.broker.sync_user_to_names",
        mock_names_task,
    )
    monkeypatch.setattr(
        "invenio_remote_user_data_kcworks.tasks.sync_user_to_names",
        mock_names_task,
    )

    response = client.get(
        "/sso/broker-callback/",
        query_string={
            "broker_token": mock_broker_token,
            "final_redirect": mock_final_redirect,
        },
    )
    app.logger.debug("got response")

    # nonce validation happened
    assert nonce_api_adapter.called
    assert nonce_api_adapter.call_count == 1
    assert nonce_api_adapter.last_request.method == "POST"
    assert nonce_api_adapter.last_request.json() == {"nonce": "test-nonce"}
    app.logger.debug("got nonce adapter")

    # user data api sync happened
    assert user_api_adapter.called
    assert user_api_adapter.call_count == 1
    app.logger.debug("got api adapter")

    # user is redirected to correct url
    assert response.status_code == 302
    assert response.headers["Location"] == mock_final_redirect

    # user was created automatically
    new_user = current_datastore.get_user_by_email(token_payload["userinfo"]["email"])
    app.logger.debug("got new user")
    assert (
        new_user.user_profile.get("identifier_kc_username")
        == token_payload["kc_username"]
    )
    assert new_user.user_profile.get("name_parts") == '{"first": "Ghost", "last": "Hc"}'
    assert new_user.user_profile.get("identifier_orcid") == "0000-0002-1825-0097"
    app.logger.debug("checked profile")

    # We don't test here for names sync behaviour. Just that task was called.
    assert mock_names_task.delay.called
    assert mock_names_task.delay.call_count == 1


def test_return_handler_existing_not_associated(
    base_app,
    db,
    client,
    user_factory,
    UserFixture,
    requests_mock,
    monkeypatch,
):
    """Test that the sso return handler behaves correctly.

    NOTE: This test uses a user that does *not* already have a UserIdentity record
    associating their account with a cilogon sub. This is mostly for legacy accounts,
    since we should now always have a UserIdentity for existing users.

    1. Decodes token
    2. Validates nonce
    3. Updates user data
    4. Redirects correctly to the final return path.
    5. UserIdentity row is created
    """
    app = base_app
    monkeypatch.setenv("COMMONS_PROFILES_API_TOKEN", secrets.token_urlsafe(32))
    mock_final_redirect = f"{app.config.get('SITE_UI_URL')}/search"

    cilogon_sub = "http://cilogon.org/serverE/users/XXXXXX"
    existing_user = user_factory(
        email="gihctester@gmail.com",
        password="password",
    )
    # Ensure prior identity association was made
    assert not UserIdentity.query.filter_by(
        id_user=existing_user.user.id, id=cilogon_sub, method="cilogon"
    ).one_or_none()

    secret = os.getenv("COMMONS_PROFILES_API_TOKEN")
    token_payload = {
        "userinfo": {
            "sub": cilogon_sub,
            "email": "gihctester@gmail.com",
            "name": "Ghost Hc",
            "idp_name": "Gmail",
        },
        "final_redirect": mock_final_redirect,
        "kc_username": "gihctester",
        "orcid": "0000-0002-1825-0097",
        "primary_email": "gihctester@gmail.com",
        "nonce": "test-nonce",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    mock_broker_token = SecureParamEncoder(secret).encode(token_payload)

    user_api_url = app.config.get("IDMS_BASE_API_URL")
    user_api_adapter = requests_mock.get(
        f"{user_api_url}subs/?sub={cilogon_sub}",
        json=IDMS_SUBS_RESPONSE_SUB,
    )

    nonce_api_adapter = requests_mock.post(
        app.config.get("SSO_BROKER_VERIFY_NONCE_URL"), json={"valid": True}
    )

    mock_names_task = MagicMock(name="sync_user_to_names")
    mock_names_task.return_value = SAMPLE_NAME_RESULT
    monkeypatch.setattr(
        "invenio_remote_user_data_kcworks.utils.broker.sync_user_to_names",
        mock_names_task,
    )
    monkeypatch.setattr(
        "invenio_remote_user_data_kcworks.tasks.sync_user_to_names",
        mock_names_task,
    )

    response = client.get(
        "/sso/broker-callback/",
        query_string={
            "broker_token": mock_broker_token,
            "final_redirect": mock_final_redirect,
        },
    )
    app.logger.debug("got response")

    # nonce validation happened
    assert nonce_api_adapter.called
    assert nonce_api_adapter.call_count == 1
    assert nonce_api_adapter.last_request.method == "POST"
    assert nonce_api_adapter.last_request.json() == {"nonce": "test-nonce"}
    app.logger.debug("got nonce adapter")

    # user data api sync happened
    assert user_api_adapter.called
    assert user_api_adapter.call_count == 1
    app.logger.debug("got api adapter")

    # user is redirected to correct url
    assert response.status_code == 302
    assert response.headers["Location"] == mock_final_redirect

    # user was created automatically
    new_user = current_datastore.get_user_by_email(token_payload["userinfo"]["email"])
    app.logger.debug("got new user")
    assert (
        new_user.user_profile.get("identifier_kc_username")
        == token_payload["kc_username"]
    )
    assert new_user.user_profile.get("name_parts") == '{"first": "Ghost", "last": "Hc"}'
    assert new_user.user_profile.get("identifier_orcid") == "0000-0002-1825-0097"
    app.logger.debug("checked profile")

    # Ensure identity association was made
    assert not UserIdentity.query.filter_by(
        id_user=existing_user.user.id, id=cilogon_sub, method="cilogon"
    ).one_or_none()

    # We don't test here for names sync behaviour. Just that task was called.
    assert mock_names_task.delay.called
    assert mock_names_task.delay.call_count == 1


def test_return_handler_expired_token(base_app, db, client, requests_mock, monkeypatch):
    """Test that the sso return handler rejects expired tokens.

    Should redirect to a 401 error page.
    """
    monkeypatch.setenv("COMMONS_PROFILES_API_TOKEN", secrets.token_urlsafe(32))
    mock_final_redirect = f"{base_app.config.get('SITE_UI_URL')}/search"

    secret = os.getenv("COMMONS_PROFILES_API_TOKEN")
    token_payload = {
        "userinfo": {
            "sub": "https://cilogon.org/serverA/users/XXXXXX",
            "email": "gihctester@gmail.com",
            "name": "Ghost Hc",
            "idp_name": "Gmail",
        },
        "final_redirect": mock_final_redirect,
        "kc_username": "gihctester",
        "primary_email": "gihctester@gmail.com",
        "nonce": "test-nonce",
        "iat": int(time.time()),
        "exp": int(time.time()) - 3600,
    }
    mock_broker_token = SecureParamEncoder(secret).encode(token_payload)

    user_api_url = base_app.config.get("IDMS_BASE_API_URL")
    user_api_adapter = requests_mock.get(
        f"{user_api_url}subs/?sub=https://cilogon.org/serverA/users/XXXXXX",
        json=IDMS_SUBS_RESPONSE_SUB,
    )

    nonce_api_adapter = requests_mock.post(
        base_app.config.get("SSO_BROKER_VERIFY_NONCE_URL"), json={"valid": True}
    )

    # NOTE: In production this error is handled by a registered error handler
    # in kcworks.ext
    with pytest.raises(BrokerPayloadExpiredError):
        client.get(
            "/sso/broker-callback/",
            query_string={
                "broker_token": mock_broker_token,
                "final_redirect": mock_final_redirect,
            },
        )

    # nonce validation did not happen
    assert not nonce_api_adapter.called
    assert nonce_api_adapter.call_count == 0

    # user data api sync did not happen
    assert not user_api_adapter.called
    assert user_api_adapter.call_count == 0

    # user was not created automatically
    assert not current_datastore.get_user_by_email(token_payload["userinfo"]["email"])


def test_return_handler_invalid_nonce(base_app, db, client, monkeypatch, requests_mock):
    """Test that the return handler rejects expired nonces.

    Should redirect to a 401 error page.
    """
    monkeypatch.setenv("COMMONS_PROFILES_API_TOKEN", secrets.token_urlsafe(32))
    mock_final_redirect = f"{base_app.config.get('SITE_UI_URL')}/search"

    secret = os.getenv("COMMONS_PROFILES_API_TOKEN")
    token_payload = {
        "userinfo": {
            "sub": "https://cilogon.org/serverA/users/XXXXXX",
            "email": "gihctester@gmail.com",
            "name": "Ghost Hc",
            "idp_name": "Gmail",
        },
        "final_redirect": mock_final_redirect,
        "kc_username": "gihctester",
        "primary_email": "gihctester@gmail.com",
        "nonce": "test-nonce",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    mock_broker_token = SecureParamEncoder(secret).encode(token_payload)

    user_api_url = base_app.config.get("IDMS_BASE_API_URL")
    user_api_adapter = requests_mock.get(
        f"{user_api_url}subs/?sub=https://cilogon.org/serverA/users/XXXXXX",
        json=IDMS_SUBS_RESPONSE_SUB,
    )

    nonce_api_adapter = requests_mock.post(
        base_app.config.get("SSO_BROKER_VERIFY_NONCE_URL"), json={"valid": False}
    )

    # NOTE: Again, this is caught by an error handler registered in production
    # by kcworks.ext
    with pytest.raises(BrokerNonceValidationError):
        client.get(
            "/sso/broker-callback/",
            query_string={
                "broker_token": mock_broker_token,
                "final_redirect": mock_final_redirect,
            },
        )

    # nonce validation did happen
    assert nonce_api_adapter.called
    assert nonce_api_adapter.call_count == 1

    # user data api sync did not happen
    assert not user_api_adapter.called
    assert user_api_adapter.call_count == 0

    # user was not created automatically
    assert not current_datastore.get_user_by_email(token_payload["userinfo"]["email"])


def test_return_handler_malformed_token(
    base_app, db, client, requests_mock, monkeypatch
):
    """Test that the return handler handles a malformed token.

    Should raise a BrokerTokenDecryptionError that will be handled by app-level error
    handlers in production and redirect to a 401 error page.
    """
    monkeypatch.setenv("COMMONS_PROFILES_API_TOKEN", secrets.token_urlsafe(32))
    mock_final_redirect = f"{base_app.config.get('SITE_UI_URL')}/search"

    nonce_api_adapter = requests_mock.post(
        base_app.config.get("SSO_BROKER_VERIFY_NONCE_URL"),
        json={"valid": True},
    )
    user_api_url = base_app.config.get("IDMS_BASE_API_URL")
    user_api_adapter = requests_mock.get(
        f"{user_api_url}subs/?sub=http://cilogon.org/serverE/users/XXXXXX",
        json=IDMS_SUBS_RESPONSE_SUB,
    )

    with pytest.raises(BrokerTokenDecryptionError):
        client.get(
            "/sso/broker-callback/",
            query_string={
                "broker_token": "not-a-valid-encrypted-broker-token",
                "final_redirect": mock_final_redirect,
            },
        )

    assert not nonce_api_adapter.called
    assert not user_api_adapter.called
