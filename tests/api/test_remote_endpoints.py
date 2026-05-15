# Part of invenio-remote-user-data-kcworks.
# Copyright (C) 2024-2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.
#

"""Integration tests for the user data sync between the KC IDP and Invenio.

The remote IDMS API is mocked in most tests; the two `test_*_kc_endpoint_*`
tests at the top of the module hit the live KC IDP and require a **real**
`COMMONS_PROFILES_API_TOKEN` (not the session placeholder from
`tests/conftest.py`) and network access.
"""

import os

import pytest
import requests

from tests.fixtures.env_defaults import commons_profiles_api_token_is_live_configured

from ..fixtures.idms import IDMS_MEMBERS_RESPONSE


@pytest.mark.skipif(
    not commons_profiles_api_token_is_live_configured(),
    reason=(
        "Live IDMS tests require a real COMMONS_PROFILES_API_TOKEN and network access."
    ),
)
def test_user_data_kc_endpoint_members(running_app):
    """Test that the production kc endpoint returns the correct data.

    The focus here is on the json schema being returned
    """
    base_url = running_app.app.config.get("IDMS_BASE_API_URL")
    url = f"{base_url}members/gihctester/"
    token = os.environ.get("COMMONS_PROFILES_API_TOKEN")
    headers = {"Authorization": f"Bearer {token}"}

    response = requests.get(url, headers=headers)

    assert response.status_code == 200
    actual_resp = response.json()
    # Members endpoint returns either a bare profile or `{"results": profile}`
    # (see `UserDataAPIClient.fetch_user_profile` / `members` branch).
    actual_data = actual_resp.get("results", actual_resp)

    assert actual_data["username"] == IDMS_MEMBERS_RESPONSE["username"]
    assert actual_data["email"] == IDMS_MEMBERS_RESPONSE["email"]
    assert actual_data["emails"] == IDMS_MEMBERS_RESPONSE["emails"]
    assert actual_data["name"] == IDMS_MEMBERS_RESPONSE["name"]
    assert actual_data["first_name"] == IDMS_MEMBERS_RESPONSE["first_name"]
    assert actual_data["last_name"] == IDMS_MEMBERS_RESPONSE["last_name"]
    assert (
        actual_data["institutional_affiliation"]
        == IDMS_MEMBERS_RESPONSE["institutional_affiliation"]
    )
    assert actual_data["orcid"] == IDMS_MEMBERS_RESPONSE["orcid"]
    assert "gravatar" in actual_data["avatar"]
    for g in actual_data["groups"]:
        assert list(g.keys()) == [
            "id",
            "group_name",
            "role",
            "url",
            "status",
            "avatar",
            "inviter_id",
            "inviter",
        ]
        assert isinstance(g["id"], int)
        if g["group_name"]:
            assert isinstance(g["group_name"], str)
    assert "MLA" in actual_data["memberships"].keys()
    assert actual_data["memberships"] == IDMS_MEMBERS_RESPONSE["memberships"]
    assert actual_data["is_superadmin"] == IDMS_MEMBERS_RESPONSE["is_superadmin"]

    assert not any(
        k for k in actual_data.keys() if k not in IDMS_MEMBERS_RESPONSE.keys()
    )


@pytest.mark.skipif(
    not commons_profiles_api_token_is_live_configured(),
    reason=(
        "Live IDMS tests require a real COMMONS_PROFILES_API_TOKEN and network access."
    ),
)
def test_user_data_kc_endpoint_subs(running_app):
    """Test that the production kc endpoint returns the correct data.

    The focus here is on the json schema being returned
    """
    base_url = running_app.app.config.get("IDMS_BASE_API_URL")
    url = f"{base_url}subs/ianscott/"
    token = os.environ.get("COMMONS_PROFILES_API_TOKEN")
    headers = {"Authorization": f"Bearer {token}"}

    response = requests.get(url, headers=headers)

    assert response.status_code == 200
    actual_resp = response.json()
    target_data = [
        d for d in actual_resp["data"] if d["profile"]["username"] == "ianscott"
    ]
    oauth_id = target_data[0]["sub"]

    response2 = requests.get(f"{base_url}subs/?sub={oauth_id}", headers=headers)
    actual_resp2 = response2.json()
    running_app.app.logger.error(actual_resp2)
    actual_data = actual_resp2["data"][0]["profile"]
    assert actual_data["username"] == "ianscott"
    assert "scottianw" in actual_data["email"]
    assert actual_data["name"] == "Ian W. Scott"
    assert actual_data["first_name"] == "Ian W."
    assert actual_data["last_name"] == "Scott"
    assert (
        actual_data["institutional_affiliation"]
        == "MESH Research, Michigan State University"
    )
    assert "0000-0002-0722" in actual_data["orcid"]
    for g in actual_data["groups"]:
        assert list(g.keys()) == [
            "id",
            "group_name",
            "role",
            "url",
            "status",
            "avatar",
            "inviter_id",
            "inviter",
        ]
        assert isinstance(g["id"], int)
        if g["group_name"]:
            assert isinstance(g["group_name"], str)
    assert "MLA" in actual_data["memberships"].keys()
    assert actual_data["is_superadmin"]


@pytest.mark.skip(reason="Not implemented")
def test_group_data_kc_endpoint():
    """Test that the production kc endpoint returns the correct data.

    The focus here is on the json schema being returned
    """
    raise NotImplementedError
