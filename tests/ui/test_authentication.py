# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or modify
# it under the terms of the MIT License; see LICENSE file for more details.

"""Authentication tests for the invenio-remote-user-data-kcworks package."""

import os
import secrets
import time
from unittest.mock import MagicMock
from urllib.parse import urlencode

import pytest
from flask import url_for
from invenio_accounts.proxies import current_datastore

from invenio_remote_user_data_kcworks.errors import (
    BrokerNonceValidationError,
    BrokerPayloadExpiredError,
)
from invenio_remote_user_data_kcworks.utils.broker import SecureParamEncoder
from tests.fixtures.idms import IDMS_SUBS_RESPONSE_SUB


def test_sso_login_success(base_app, client, requests_mock):
    """Test that the sso login check works for anonymous visitor.

    - call front page (ui) view function with client
        - ensure client does not have session cookie
        - ensure client is not logged in
    - check that sso session check is made (Profiles url is called)
    """
    sso_check_url = base_app.config.get("SSO_BROKER_SILENT_LOGIN_URL")
    expected_final_redirect = base_app.config["SITE_UI_URL"] + "/search"
    expected_return_to = url_for(
        "invenio_remote_user_data_kcworks_sso.broker_callback",
        _external=True,
        _scheme="https",
    )
    query = urlencode({
        "return_to": expected_return_to,
        "final_redirect": expected_final_redirect,
    })
    request_url = f"{sso_check_url}?{query}"
    #
    # silent_check_adapter = requests_mock.request(
    #     "POST",
    #     request_url,
    #     headers={"Cookie": ""},
    # )
    #
    response = client.get("/search", headers={"Cookie": ""})
    assert response.status_code == 302
    assert response.headers["Location"] == request_url

    # assert silent_check_adapter.called
    # assert silent_check_adapter.call_count == 1
    #
    # req = silent_check_adapter.last_request
    # assert req.method == "GET"
    # assert req.url == request_url


def test_sso_pass_with_cookie(base_app_with_templates, client):
    """Test that the sso login check is skipped when the timeout cookie is not expired.

    - call front page (ui) view function with client
        - ensure client does not have session cookie
        - ensure client is not logged in
    - check that sso session check is made (Profiles url is called)
    """
    base_app = base_app_with_templates
    expected_final_redirect = base_app.config["SITE_UI_URL"] + "/search"
    cookie_name = base_app.config["SSO_BROKER_RETRY_COOKIE_NAME"]
    cookie_val = str(int(time.time()))
    client.set_cookie(cookie_name, cookie_val)

    response = client.get("/search")

    assert response.request.url == expected_final_redirect

    # cookie is not re-set
    set_cookie = response.headers.getlist("Set-Cookie")
    assert not any(
        s for s in set_cookie if s.startswith(cookie_name) and cookie_val in s
    )

    # cookie remains on client
    assert (
        client.get_cookie(cookie_name, domain="localhost", path="/").value == cookie_val
    )

    assert response.status_code == 200


def test_sso_check_pass_logged_in(base_app_with_templates, client, monkeypatch):
    """Test that the sso login check is skipped when a user is logged in.

    - call search page (ui) view function with client
        - ensure client *does* a valid session cookie
        - ensure client *does not* have the _sso_checked cookie set
    - check that sso session check is *not* made (Profiles url is *not* called)
    - check that we ended up at the final redirect
    """
    base_app = base_app_with_templates

    user = MagicMock()
    user.id = "1"
    user.is_authenticated = True
    user.is_anonymous = False
    user.get_id.return_value = "1"

    expected_final_redirect = base_app.config["SITE_UI_URL"] + "/search"

    ds = client.application.extensions["security"].datastore
    monkeypatch.setattr(
        ds, "find_user", lambda **kw: user if kw.get("id") == "1" else None
    )

    with client.session_transaction() as session:
        session["_user_id"] = "1"
        session["_fresh"] = True

    response = client.get("/search")
    assert response.request.url == expected_final_redirect
    assert not client.get_cookie(base_app.config["SSO_BROKER_RETRY_COOKIE_NAME"])
    assert response.status_code == 200


def test_sso_check_pass_api(base_app_with_templates, client):
    """Test that the sso login check is skipped on api requests."""
    base_app = base_app_with_templates

    target_endpoint = base_app.config["SITE_API_URL"] + "/records"
    response = client.get(target_endpoint, headers={"Cookie": ""})

    assert response.status_code == 200
    assert not response.headers.get("Location")
    assert response.request.url == target_endpoint
    assert not client.get_cookie(base_app.config["SSO_BROKER_RETRY_COOKIE_NAME"])


def test_login_redirect_to_cilogon():
    """Test that the login handler redirects out to cilogon."""
    ...


def test_return_handler_new_user(base_app, db, client, requests_mock, monkeypatch):
    """Test that the sso return handler behaves correctly.

    1. Decodes token
    2. Validates nonce
    3. Creates a new user for the missing one
    4. Redirects correctly to the final return path.
    """
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

    user_api_url = base_app.config.get("IDMS_BASE_API_URL")
    user_api_adapter = requests_mock.get(
        f"{user_api_url}subs/?sub=http://cilogon.org/serverE/users/XXXXXX",
        json=IDMS_SUBS_RESPONSE_SUB,
    )

    nonce_api_adapter = requests_mock.post(
        base_app.config.get("SSO_BROKER_VERIFY_NONCE_URL"), json={"valid": True}
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
    # FIXME: Eliminate the redundant API call here
    # Called once for new user creation, then again
    # on login.
    assert user_api_adapter.call_count == 2

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


def test_return_handler_existing_user(
    running_app, db, client, user_factory, requests_mock, monkeypatch, search_clear
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
    app = running_app.app
    monkeypatch.setenv("COMMONS_PROFILES_API_TOKEN", secrets.token_urlsafe(32))
    mock_final_redirect = f"{app.config.get('SITE_UI_URL')}/search"

    _ = user_factory(
        email="gihctester@gmail.com",
        oauth_src="cilogon",
        oauth_id="http://cilogon.org/serverE/users/XXXXXX",
    )

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
        "orcid": "0000-0002-1825-0097",
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
    assert new_user.user_profile.get("identifier_orcid") == "0000-0002-1825-0097"


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


def test_return_handler_malformed_token():
    """Test that the return handler handles a malformed token.

    Should redirect to a 401 error page.
    """
    ...


def test_return_handler_failure():
    """Test that the return handler deals with negative Profiles responses.

    Should redirect to a 401 error page.
    """
    ...
