# Part of invenio-remote-user-data-kcworks.
# Copyright (C) 2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""HTTP-level tests for `UserDataAPIClient` using `requests_mock`.

Uses `base_app` only (no full `app` / broker / search chain), matching
`tests/api/user_data/test_auth_update_transforms.py`.

See Also:
    This package `docs/private/functionality-test-remediation-plan.md`
    (planning + coverage gaps; canonical path under dependency root).
"""

from __future__ import annotations

import json
import logging
import os

import pytest
import requests

from invenio_remote_user_data_kcworks.client import UserDataAPIClient
from invenio_remote_user_data_kcworks.config import UserDataEvent, UserDataStatus
from invenio_remote_user_data_kcworks.types.profiles_api import APIResponse, Profile
from tests.fixtures.idms import minimal_api_response, minimal_profile


def _caplog_messages(caplog) -> str:
    """Join formatted log lines for substring assertions.

    Returns:
        Single string of `getMessage()` lines for easy `in` checks.
    """
    return "\n".join(record.getMessage() for record in caplog.records)


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


def _assert_one_post_with_profiles_headers(requests_mock, *, url: str) -> None:
    """Assert exactly one POST to `url` with bearer + JSON + Accept headers."""
    assert len(requests_mock.request_history) == 1
    req = requests_mock.last_request
    assert req is not None
    assert req.method == "POST"
    assert req.url == url
    token = os.environ["COMMONS_PROFILES_API_TOKEN"]
    assert req.headers.get("Authorization") == f"Bearer {token}"
    assert req.headers.get("Content-Type") == "application/json"
    assert req.headers.get("Accept") == "application/json"


def _logout_success_json(*, user_name: str, user_agent: str) -> dict:
    """Minimal 2xx JSON body that satisfies `send_logout_to_profiles` checks.

    Returns:
        Dict shaped like a successful Profiles logout response body.
    """
    return {
        "message": "Action successfully triggered.",
        "data": {
            "user": {"user": user_name, "url": f"/profiles/{user_name}/"},
            "user_agent": user_agent,
            "app": ["Profiles", "Works", "WordPress"],
        },
    }


_SUB_FOR_SUBS_LIST = "https://cilogon.org/http/urn/mace/internet2.edu/idp/test/subject"


@pytest.mark.usefixtures("base_app")
class TestUserDataAPIClientFetchProfile:
    """Tests for `fetch_user_profile` with `sub_id` (`subs/?sub=`)."""

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


@pytest.mark.usefixtures("base_app")
class TestUserDataAPIClientFetchProfileByUsername:
    """Tests for `fetch_user_profile` with `kc_username` (subs vs members URL)."""

    def test_fetch_by_username_subs_endpoint_returns_api_response(
        self, base_app, requests_mock
    ):
        """Assert `use_sub_endpoint=True` hits `GET …/subs/{user}/` and parses list."""
        kc_username = "memberu"
        base = base_app.config["IDMS_BASE_API_URL"]
        url = f"{base}subs/{kc_username}/"
        response_json = minimal_api_response(
            "https://idp.example/sub-1",
            username=kc_username,
            name="Member User",
            email="memberu@example.org",
        ).model_dump(mode="json")
        requests_mock.get(url, json=response_json)
        with base_app.app_context():
            out = UserDataAPIClient.fetch_user_profile(
                kc_username=kc_username,
                use_sub_endpoint=True,
            )
        _assert_one_get_with_profiles_headers(requests_mock, url=url)
        assert isinstance(out, APIResponse)
        assert out.data[0].profile.username == kc_username

    def test_fetch_by_username_members_endpoint_returns_profile(
        self, base_app, requests_mock
    ):
        """Assert members branch uses `GET …/members/{user}/` and parses `Profile`."""
        kc_username = "sluguser"
        base = base_app.config["IDMS_BASE_API_URL"]
        url = f"{base}members/{kc_username}/"
        body = minimal_profile(username=kc_username).model_dump(mode="json")
        requests_mock.get(url, json=body)
        with base_app.app_context():
            out = UserDataAPIClient.fetch_user_profile(kc_username=kc_username)
        _assert_one_get_with_profiles_headers(requests_mock, url=url)
        assert isinstance(out, Profile)
        assert out.username == kc_username

    def test_fetch_by_username_members_wraps_results_key(self, base_app, requests_mock):
        """Assert `Profile` is built from `results` when the API nests the object."""
        kc_username = "nestedu"
        base = base_app.config["IDMS_BASE_API_URL"]
        url = f"{base}members/{kc_username}/"
        inner = minimal_profile(username=kc_username).model_dump(mode="json")
        requests_mock.get(url, json={"results": inner})
        with base_app.app_context():
            out = UserDataAPIClient.fetch_user_profile(kc_username=kc_username)
        _assert_one_get_with_profiles_headers(requests_mock, url=url)
        assert isinstance(out, Profile)
        assert out.username == kc_username


@pytest.mark.usefixtures("base_app")
class TestUserDataAPIClientSendLogoutToProfiles:
    """Tests for `send_logout_to_profiles` (`POST …/actions/logout/`)."""

    def test_send_logout_posts_json_and_returns_true_on_valid_body(
        self, base_app, requests_mock
    ):
        """Assert POST body, headers, and success when Profiles echoes user + agent."""
        user_name = "logout_user"
        user_agent = "LogoutTestAgent/1.0"
        base = base_app.config["IDMS_BASE_API_URL"]
        post_url = f"{base}actions/logout/"
        requests_mock.post(
            post_url,
            json=_logout_success_json(user_name=user_name, user_agent=user_agent),
        )
        with base_app.app_context():
            with base_app.test_request_context(
                environ_overrides={"HTTP_USER_AGENT": user_agent},
            ):
                ok = UserDataAPIClient.send_logout_to_profiles(user_name)
        assert ok is True
        _assert_one_post_with_profiles_headers(requests_mock, url=post_url)
        body = json.loads(requests_mock.last_request.body.decode())
        assert body["user_name"] == user_name
        assert body["user_agent"] == user_agent

    def test_send_logout_returns_false_when_profiles_body_mismatches(
        self, base_app, requests_mock
    ):
        """Assert 200 with wrong echo fields yields `False` (client rejects body)."""
        user_name = "logout_user"
        user_agent = "LogoutTestAgent/1.0"
        base = base_app.config["IDMS_BASE_API_URL"]
        post_url = f"{base}actions/logout/"
        bad = _logout_success_json(user_name=user_name, user_agent=user_agent)
        bad["data"]["user"]["user"] = "someone_else"
        requests_mock.post(post_url, json=bad)
        with base_app.app_context():
            with base_app.test_request_context(
                environ_overrides={"HTTP_USER_AGENT": user_agent},
            ):
                ok = UserDataAPIClient.send_logout_to_profiles(user_name)
        assert ok is False
        assert len(requests_mock.request_history) == 1

    def test_send_logout_returns_false_on_non_2xx(self, base_app, requests_mock):
        """Assert non-2xx HTTP without raising (boolean contract)."""
        base = base_app.config["IDMS_BASE_API_URL"]
        post_url = f"{base}actions/logout/"
        requests_mock.post(post_url, status_code=401, text="unauthorized")
        with base_app.app_context():
            with base_app.test_request_context(
                environ_overrides={"HTTP_USER_AGENT": "UA"},
            ):
                ok = UserDataAPIClient.send_logout_to_profiles("u1")
        assert ok is False

    def test_send_logout_returns_false_on_request_exception(
        self, base_app, requests_mock, caplog
    ):
        """Transport error → `False` and error log (no raise)."""
        base = base_app.config["IDMS_BASE_API_URL"]
        post_url = f"{base}actions/logout/"
        requests_mock.post(post_url, exc=requests.ConnectionError("down"))
        with caplog.at_level(logging.ERROR):
            with base_app.app_context():
                with base_app.test_request_context(
                    environ_overrides={"HTTP_USER_AGENT": "UA"},
                ):
                    ok = UserDataAPIClient.send_logout_to_profiles("u1")
        assert ok is False
        assert "Error sending logout to Profiles API" in _caplog_messages(caplog)


@pytest.mark.usefixtures("base_app")
class TestUserDataAPIClientSendUserStatusCallback:
    """Tests for `send_user_status_callback` (`POST …/members/…/works/status`)."""

    def test_send_status_posts_expected_url_and_json(
        self, base_app, requests_mock, caplog
    ):
        """Assert URL, JSON body, POST headers, and debug `ok` log."""
        sub = "https://idp.example/subject-abc"
        username = "kc_member"
        base = base_app.config["IDMS_BASE_API_URL"]
        post_url = f"{base}members/{username}/works/status"
        requests_mock.post(post_url, status_code=204)
        with caplog.at_level(logging.DEBUG):
            with base_app.app_context():
                ok = UserDataAPIClient.send_user_status_callback(
                    sub=sub,
                    username=username,
                    status=UserDataStatus.PROCESSED,
                    event=UserDataEvent.CREATED,
                )
        assert ok is True
        _assert_one_post_with_profiles_headers(requests_mock, url=post_url)
        body = json.loads(requests_mock.last_request.body.decode())
        assert body["sub"] == sub
        assert body["username"] == username
        assert body["status"] == UserDataStatus.PROCESSED.value
        assert body["event"] == UserDataEvent.CREATED.value
        assert "retry_at" not in body and "note" not in body
        assert "send_user_status_callback: ok" in _caplog_messages(caplog)

    def test_send_status_unknown_slug_when_username_none(
        self, base_app, requests_mock, caplog
    ):
        """Assert `unknown` slug, body `sub`, and debug `ok` log."""
        sub = "https://idp.example/sub-only"
        base = base_app.config["IDMS_BASE_API_URL"]
        post_url = f"{base}members/unknown/works/status"
        requests_mock.post(post_url, status_code=200)
        with caplog.at_level(logging.DEBUG):
            with base_app.app_context():
                ok = UserDataAPIClient.send_user_status_callback(
                    sub=sub,
                    username=None,
                    status=UserDataStatus.FAILED,
                    event=UserDataEvent.UPDATED,
                    retry_at="2026-01-01T00:00:00Z",
                    note="unit-test",
                )
        assert ok is True
        body = json.loads(requests_mock.last_request.body.decode())
        assert body["username"] is None
        assert body["retry_at"] == "2026-01-01T00:00:00Z"
        assert body["note"] == "unit-test"
        assert "send_user_status_callback: ok" in _caplog_messages(caplog)

    def test_send_status_empty_sub_short_circuits(
        self, base_app, requests_mock, caplog
    ):
        """Assert empty `sub` yields `False`, no HTTP, and a warning log."""
        with caplog.at_level(logging.WARNING):
            with base_app.app_context():
                ok = UserDataAPIClient.send_user_status_callback(
                    sub="",
                    username="x",
                    status=UserDataStatus.PROCESSED,
                    event=UserDataEvent.CREATED,
                )
        assert ok is False
        assert len(requests_mock.request_history) == 0
        assert "send_user_status_callback: empty sub" in _caplog_messages(caplog)

    def test_send_status_invalid_status_returns_false(
        self, base_app, requests_mock, caplog
    ):
        """Assert non-`UserDataStatus` is rejected without POST; error log."""
        with caplog.at_level(logging.ERROR):
            with base_app.app_context():
                ok = UserDataAPIClient.send_user_status_callback(
                    sub="https://idp.example/s",
                    username="u",
                    status="PROCESSED",  # type: ignore[arg-type]
                    event=UserDataEvent.CREATED,
                )
        assert ok is False
        assert len(requests_mock.request_history) == 0
        assert "send_user_status_callback: invalid status" in _caplog_messages(caplog)

    def test_send_status_invalid_event_returns_false(
        self, base_app, requests_mock, caplog
    ):
        """Assert non-`UserDataEvent` is rejected without POST; error log."""
        with caplog.at_level(logging.ERROR):
            with base_app.app_context():
                ok = UserDataAPIClient.send_user_status_callback(
                    sub="https://idp.example/s",
                    username="u",
                    status=UserDataStatus.PROCESSED,
                    event="created",  # type: ignore[arg-type]
                )
        assert ok is False
        assert len(requests_mock.request_history) == 0
        assert "send_user_status_callback: invalid event" in _caplog_messages(caplog)

    def test_send_status_skips_when_token_missing(
        self, base_app, requests_mock, monkeypatch, caplog
    ):
        """Assert missing bearer env skips POST and logs a warning."""
        monkeypatch.delenv("COMMONS_PROFILES_API_TOKEN", raising=False)
        with caplog.at_level(logging.WARNING):
            with base_app.app_context():
                ok = UserDataAPIClient.send_user_status_callback(
                    sub="https://idp.example/s",
                    username="u",
                    status=UserDataStatus.PROCESSED,
                    event=UserDataEvent.CREATED,
                )
        assert ok is False
        assert len(requests_mock.request_history) == 0
        logs = _caplog_messages(caplog)
        assert "send_user_status_callback: IDMS_BASE_API_URL or" in logs

    def test_send_status_skips_when_idms_base_missing(
        self, base_app, requests_mock, caplog
    ):
        """Assert missing `IDMS_BASE_API_URL` yields `False`, no POST, warning log."""
        base = base_app.config["IDMS_BASE_API_URL"]
        base_app.config["IDMS_BASE_API_URL"] = ""
        try:
            with caplog.at_level(logging.WARNING):
                with base_app.app_context():
                    ok = UserDataAPIClient.send_user_status_callback(
                        sub="https://idp.example/s",
                        username="u",
                        status=UserDataStatus.PROCESSED,
                        event=UserDataEvent.CREATED,
                    )
            assert ok is False
            assert len(requests_mock.request_history) == 0
            logs = _caplog_messages(caplog)
            assert "send_user_status_callback: IDMS_BASE_API_URL or" in logs
        finally:
            base_app.config["IDMS_BASE_API_URL"] = base

    def test_send_status_retries_then_succeeds(
        self, base_app, requests_mock, monkeypatch, caplog
    ):
        """Failed attempt logs HTTP warning; success logs debug `ok`."""
        monkeypatch.setattr(
            "invenio_remote_user_data_kcworks.client.time.sleep",
            lambda *_args, **_kwargs: None,
        )
        sub = "https://idp.example/sub-retry"
        username = "retryuser"
        base = base_app.config["IDMS_BASE_API_URL"]
        post_url = f"{base}members/{username}/works/status"
        requests_mock.post(
            post_url,
            [
                {"status_code": 503, "text": "busy"},
                {"status_code": 200},
            ],
        )
        with caplog.at_level(logging.DEBUG):
            with base_app.app_context():
                ok = UserDataAPIClient.send_user_status_callback(
                    sub=sub,
                    username=username,
                    status=UserDataStatus.PROCESSED,
                    event=UserDataEvent.CREATED,
                    max_attempts=3,
                )
        assert ok is True
        assert len(requests_mock.request_history) == 2
        for req in requests_mock.request_history:
            assert req.method == "POST"
            assert req.url == post_url
        logs = _caplog_messages(caplog)
        assert "send_user_status_callback: HTTP 503" in logs
        assert "send_user_status_callback: ok" in logs

    def test_send_status_exhausted_attempts_logs_error(
        self, base_app, requests_mock, monkeypatch, caplog
    ):
        """All non-2xx attempts produce warnings then a final error log."""
        monkeypatch.setattr(
            "invenio_remote_user_data_kcworks.client.time.sleep",
            lambda *_args, **_kwargs: None,
        )
        sub = "https://idp.example/sub-dead"
        username = "deaduser"
        base = base_app.config["IDMS_BASE_API_URL"]
        post_url = f"{base}members/{username}/works/status"
        requests_mock.post(
            post_url,
            [
                {"status_code": 503, "text": "a"},
                {"status_code": 503, "text": "b"},
            ],
        )
        with caplog.at_level(logging.DEBUG):
            with base_app.app_context():
                ok = UserDataAPIClient.send_user_status_callback(
                    sub=sub,
                    username=username,
                    status=UserDataStatus.PROCESSED,
                    event=UserDataEvent.CREATED,
                    max_attempts=2,
                )
        assert ok is False
        assert len(requests_mock.request_history) == 2
        logs = _caplog_messages(caplog)
        assert logs.count("send_user_status_callback: HTTP 503") == 2
        assert "send_user_status_callback: gave up after 2 attempts" in logs
        assert any(
            r.levelno >= logging.ERROR and "gave up" in r.getMessage()
            for r in caplog.records
        )

    def test_send_status_transport_failure_then_succeeds(
        self, base_app, requests_mock, monkeypatch, caplog
    ):
        """First POST raises; second succeeds (warning then debug `ok`)."""
        monkeypatch.setattr(
            "invenio_remote_user_data_kcworks.client.time.sleep",
            lambda *_args, **_kwargs: None,
        )
        sub = "https://idp.example/sub-transport"
        username = "transportuser"
        base = base_app.config["IDMS_BASE_API_URL"]
        post_url = f"{base}members/{username}/works/status"
        requests_mock.post(
            post_url,
            [
                {"exc": requests.ConnectionError("reset")},
                {"status_code": 200},
            ],
        )
        with caplog.at_level(logging.DEBUG):
            with base_app.app_context():
                ok = UserDataAPIClient.send_user_status_callback(
                    sub=sub,
                    username=username,
                    status=UserDataStatus.PROCESSED,
                    event=UserDataEvent.CREATED,
                    max_attempts=3,
                )
        assert ok is True
        assert len(requests_mock.request_history) == 2
        logs = _caplog_messages(caplog)
        assert "send_user_status_callback:" in logs and "on attempt" in logs
        assert "send_user_status_callback: ok" in logs
