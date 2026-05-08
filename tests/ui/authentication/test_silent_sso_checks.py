# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute
# and/or modify it under the terms of the MIT License; see LICENSE file for more
# details.

"""Test silent SSO session checking for the invenio-remote-user-data-kcworks package.

These tests aim to be as lightweight as possible and so *do not* pull in the search
index fixture. A full live workflow test is included in the UI integration test module.
"""

import time
from unittest.mock import MagicMock
from urllib.parse import urlencode

from flask import url_for


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

    response = client.get("/search", headers={"Cookie": ""})
    assert response.status_code == 302
    assert response.headers["Location"] == request_url


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
