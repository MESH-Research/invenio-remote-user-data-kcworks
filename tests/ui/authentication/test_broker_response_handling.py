# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""Test SSO broker callback response handling.

The broker payload processing test module focuses on the case when a remote SSO
session is active and a token is provided by the broker. This module focuses on the
broker behaviour when a valid session token is *not* provided. Covers cases where:

- the broker indicates no SSO session is active for the user
- the broker supplies a token but *also* indicates that no SSO session is active
- the broker does not signal that a session was absent, but also doesn't include
  a token.

These tests aim to be as lightweight as possible and so *do not* pull in the search
index fixture. A full live workflow test is included in the UI integration test module.
"""

import os
import secrets
import time

import pytest
from invenio_accounts.proxies import current_datastore

from invenio_remote_user_data_kcworks.errors import (
    BrokerTokenMissingError,
)
from invenio_remote_user_data_kcworks.utils.broker import SecureParamEncoder
from tests.fixtures.idms import IDMS_SUBS_RESPONSE_SUB


def test_broker_callback_missing_token(base_app, client):
    """When no broker_token or no_session raises BrokerTokenMissingError.

    Covers the first branch of _sso_broker_callback; outer view re-raises for
    app-level handlers.
    """
    final = f"{base_app.config['SITE_UI_URL']}/search"

    with pytest.raises(BrokerTokenMissingError):
        client.get(
            "/sso/broker-callback/",
            query_string={"final_redirect": final},
        )


def test_broker_callback_no_sso_session(base_app, client):
    """When no sso session present, redirects to final_redirect and sets cookie.

    When the Profiles response includes param `no_session=1` the view
    - sets the _sso_checked cookie
    - redirects to the path in the `final_redirect` param

    Covers the else branch of _sso_broker_callback (no token processing).
    """
    mock_final_redirect = f"{base_app.config['SITE_UI_URL']}/search"
    sso_checked_cookie_name = base_app.config["SSO_BROKER_RETRY_COOKIE_NAME"]

    response = client.get(
        "/sso/broker-callback/",
        query_string={
            "no_session": "1",
            "final_redirect": mock_final_redirect,
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"] == mock_final_redirect

    set_cookies = response.headers.getlist("Set-Cookie")
    assert any(sso_checked_cookie_name in c for c in set_cookies)
    assert int(client.get_cookie(sso_checked_cookie_name).value) - time.time() < 100

    with client.session_transaction() as sess:
        assert sess.get("_user_id") is None


def test_broker_callback_no_session_supersedes_broker_token(
    base_app, db, client, requests_mock, monkeypatch
):
    """When no sso session present, does not process any returned broker_token.

    When `no_session=1` in the request params, ignore any token that is sent.

    Ensures downstream nonce check and user data API request are not called
    and no user is created from the token or logged in.

    `_sso_checked` cookie should also be set correctly.
    """
    monkeypatch.setenv("COMMONS_PROFILES_API_TOKEN", secrets.token_urlsafe(32))
    mock_final_redirect = f"{base_app.config['SITE_UI_URL']}/search"

    secret = os.getenv("COMMONS_PROFILES_API_TOKEN")
    token_payload = {
        "userinfo": {
            "sub": "http://cilogon.org/serverE/users/XXXXXX",
            "email": "nosession_supersedes_token_test@gmail.com",
            "name": "Ghost Hc",
            "idp_name": "Gmail",
        },
        "final_redirect": mock_final_redirect,
        "kc_username": "nosession_supersedes",
        "primary_email": "nosession_supersedes_token_test@gmail.com",
        "nonce": "test-nonce",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    mock_broker_token = SecureParamEncoder(secret).encode(token_payload)

    nonce_api_adapter = requests_mock.post(
        base_app.config.get("SSO_BROKER_VERIFY_NONCE_URL"),
        json={"valid": True},
    )
    user_api_url = base_app.config.get("IDMS_BASE_API_URL")
    user_api_adapter = requests_mock.get(
        f"{user_api_url}subs/?sub=http://cilogon.org/serverE/users/XXXXXX",
        json=IDMS_SUBS_RESPONSE_SUB,
    )

    response = client.get(
        "/sso/broker-callback/",
        query_string={
            "broker_token": mock_broker_token,
            "no_session": "1",
            "final_redirect": mock_final_redirect,
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"] == mock_final_redirect

    assert not nonce_api_adapter.called
    assert not user_api_adapter.called
    assert not current_datastore.get_user_by_email(token_payload["userinfo"]["email"])

    sso_checked_cookie_name = base_app.config["SSO_BROKER_RETRY_COOKIE_NAME"]
    set_cookies = response.headers.getlist("Set-Cookie")
    assert any(sso_checked_cookie_name in c for c in set_cookies)

    assert int(client.get_cookie(sso_checked_cookie_name).value) - time.time() < 100

    with client.session_transaction() as sess:
        assert sess.get("_user_id") is None
