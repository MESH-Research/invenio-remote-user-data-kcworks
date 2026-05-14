# Part of invenio-remote-user-data-kcworks.
# Copyright (C) 2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""HTTP-level tests for `UserDataAPIClient` using `requests_mock`.

Exercises `fetch_user_profile` without calling live IDMS. Uses
`base_app` only (no full `app` / broker / search chain), matching
`tests/api/user_data/test_auth_update_transforms.py`.

See Also:
    `docs/private/functionality-test-remediation-plan.md` (P2 — client
    HTTP failure matrix).
"""

from __future__ import annotations

import os

import pytest
import requests

from invenio_remote_user_data_kcworks.client import UserDataAPIClient
from invenio_remote_user_data_kcworks.types.profiles_api import APIResponse
from tests.fixtures.idms import minimal_api_response


def _assert_one_get_with_profiles_headers(requests_mock, *, url: str) -> None:
    """Assert exactly one GET to `url` with the client’s profiles headers."""
    assert len(requests_mock.request_history) == 1
    req = requests_mock.last_request
    assert req is not None
    assert req.method == "GET"
    assert req.url == url
    token = os.environ["COMMONS_PROFILES_API_TOKEN"]
    assert req.headers.get("Authorization") == f"Bearer {token}"
    assert req.headers.get("Content-Type") == "application/json"


_SUB_FOR_SUBS_LIST = (
    "https://cilogon.org/http/urn/mace/internet2.edu/idp/test/subject"
)


@pytest.mark.usefixtures("base_app")
class TestUserDataAPIClientFetchProfile:
    """Tests for `UserDataAPIClient.fetch_user_profile` (subs-by-subject).

    Uses `base_app` + `app_context`; no Celery, DB, or RabbitMQ from the
    full `app` fixture chain.
    """

    def test_fetch_by_sub_id_parses_api_response(self, base_app, requests_mock):
        """Assert one GET with bearer JSON headers and parsed `APIResponse`.

        Args:
            base_app: Flask application fixture (pytest-invenio).
            requests_mock: `requests` adapter mock.
        """
        response_json = minimal_api_response(
            _SUB_FOR_SUBS_LIST,
            username="jdoe",
            name="Jane Doe",
            email="jdoe@example.org",
            first_name="Jane",
            last_name="Doe",
            institutional_affiliation="Example University",
            orcid="0000-0002-1825-0097",
        ).model_dump(mode="json")
        base = base_app.config["IDMS_BASE_API_URL"]
        url = f"{base}subs/?sub={_SUB_FOR_SUBS_LIST}"
        requests_mock.get(url, json=response_json)
        with base_app.app_context():
            out = UserDataAPIClient.fetch_user_profile(sub_id=_SUB_FOR_SUBS_LIST)
        _assert_one_get_with_profiles_headers(requests_mock, url=url)
        assert isinstance(out, APIResponse)
        assert len(out.data) == 1
        assert out.data[0].profile.username == "jdoe"
        assert out.meta.authorized is True

    def test_fetch_by_sub_http_error_propagates(self, base_app, requests_mock):
        """Assert 502 still follows one GET with profiles headers, then `HTTPError`.

        Args:
            base_app: Flask application fixture (pytest-invenio).
            requests_mock: `requests` adapter mock.
        """
        sub_id = "sub-502"
        base = base_app.config["IDMS_BASE_API_URL"]
        url = f"{base}subs/?sub={sub_id}"
        requests_mock.get(
            url,
            status_code=502,
            reason="Bad Gateway",
            text="upstream",
        )
        with base_app.app_context():
            with pytest.raises(requests.HTTPError):
                UserDataAPIClient.fetch_user_profile(sub_id=sub_id)
        _assert_one_get_with_profiles_headers(requests_mock, url=url)

    def test_fetch_by_sub_timeout_propagates(self, base_app, requests_mock):
        """Assert timeout still follows one GET with profiles headers.

        Args:
            base_app: Flask application fixture (pytest-invenio).
            requests_mock: `requests` adapter mock.
        """
        sub_id = "sub-timeout"
        base = base_app.config["IDMS_BASE_API_URL"]
        url = f"{base}subs/?sub={sub_id}"
        requests_mock.get(
            url,
            exc=requests.exceptions.ReadTimeout("timed out"),
        )
        with base_app.app_context():
            with pytest.raises(requests.Timeout):
                UserDataAPIClient.fetch_user_profile(sub_id=sub_id)
        _assert_one_get_with_profiles_headers(requests_mock, url=url)

    def test_fetch_by_sub_invalid_api_response_json_returns_none(
        self, base_app, requests_mock
    ):
        """Assert invalid JSON shape: one GET, then `None`.

        Args:
            base_app: Flask application fixture (pytest-invenio).
            requests_mock: `requests` adapter mock.
        """
        sub_id = "sub-badshape"
        base = base_app.config["IDMS_BASE_API_URL"]
        url = f"{base}subs/?sub={sub_id}"
        requests_mock.get(
            url,
            json={
                "data": "not-a-list",
                "meta": {"authorized": True},
                "next": None,
                "previous": None,
            },
            status_code=200,
        )
        with base_app.app_context():
            out = UserDataAPIClient.fetch_user_profile(sub_id=sub_id)
        _assert_one_get_with_profiles_headers(requests_mock, url=url)
        assert out is None
