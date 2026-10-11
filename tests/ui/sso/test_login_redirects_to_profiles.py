# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""Explicit `/login` sends the browser to the Profiles broker login URL.

Flask-Security’s `security.login` view is replaced by `sso_broker_login`
(`ACCOUNTS_LOGIN_VIEW_FUNCTION`). There is no separate intermediate local
route: `GET /login/` *is* that handler, and it 302s out to
`SSO_BROKER_LOGIN_URL` with `return_to` (callback) and `final_redirect`.

The silent-SSO `before_request` hook would otherwise steal an anonymous
`/login` hit and send the user to the *silent* broker URL. These tests set
the retry cookie first so the explicit login path is exercised.

Covers:

- `GET /login/` (with a recent SSO retry cookie) redirects to Profiles
  `SSO_BROKER_LOGIN_URL`, not the silent-login URL.
- Query string includes `return_to` = broker callback and `final_redirect`
  from the `next` parameter.
"""

import time
from urllib.parse import parse_qs, urlparse

from flask import url_for


def test_login_redirects_to_profiles_broker_login_url(base_app, client):
    """`/login` is the broker handler: 302 to Profiles login with callback params."""
    cookie_name = base_app.config["SSO_BROKER_RETRY_COOKIE_NAME"]
    client.set_cookie(cookie_name, str(int(time.time())))

    final = f"{base_app.config['SITE_UI_URL']}/search"
    response = client.get(f"/login/?next={final}")

    assert response.status_code == 302
    location = response.headers["Location"]
    parsed = urlparse(location)

    broker_login = base_app.config["SSO_BROKER_LOGIN_URL"]
    silent_login = base_app.config["SSO_BROKER_SILENT_LOGIN_URL"]
    assert location.startswith(broker_login)
    assert not location.startswith(silent_login)

    query = parse_qs(parsed.query)
    expected_return_to = url_for(
        "invenio_remote_user_data_kcworks_sso.broker_callback",
        _external=True,
        _scheme="https",
    )
    assert query.get("return_to") == [expected_return_to]
    assert query.get("final_redirect") == [final]


def test_login_without_next_still_redirects_to_profiles_broker(base_app, client):
    """`/login` without `next` still leaves for Profiles (non-silent) login."""
    cookie_name = base_app.config["SSO_BROKER_RETRY_COOKIE_NAME"]
    client.set_cookie(cookie_name, str(int(time.time())))

    response = client.get("/login/")

    assert response.status_code == 302
    location = response.headers["Location"]
    assert location.startswith(base_app.config["SSO_BROKER_LOGIN_URL"])
    assert not location.startswith(base_app.config["SSO_BROKER_SILENT_LOGIN_URL"])

    query = parse_qs(urlparse(location).query)
    assert "return_to" in query
    # `final_redirect` may be empty/absent depending on safe_redirect_target(None).
    assert query["return_to"][0].endswith("/sso/broker-callback/")
