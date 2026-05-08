# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""End-to-end integration tests for invenio-remote-user-data-kcworks."""

import os
import secrets
import time

from invenio_access.permissions import system_identity
from invenio_accounts.proxies import current_datastore
from invenio_records_resources.proxies import current_service_registry

from invenio_remote_user_data_kcworks.utils.broker import SecureParamEncoder
from tests.fixtures.idms import IDMS_SUBS_RESPONSE_SUB


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

    # user's name record was synced properly
    # NOTE: This is actually testing sync for missing name on login!
    names_service = current_service_registry.get("names")
    assert (
        names_service.read(system_identity, token_payload["kc_username"])["id"]
        == "gihctester"
    )
