# Part of invenio-remote-user-data-kcworks.
# Copyright (C) 2026, MESH Research.
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""HTTP-level tests for `SessionBrokerAPIClient` (`requests_mock`, no live broker).

Uses `base_app` + `app_context` only (no full `app` / broker / search chain).

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

from invenio_remote_user_data_kcworks.client import SessionBrokerAPIClient


def _caplog_messages(caplog) -> str:
    """Join formatted log lines for substring assertions.

    Returns:
        Single string of `getMessage()` lines for easy `in` checks.
    """
    return "\n".join(record.getMessage() for record in caplog.records)


def _silent_login_prepared_url(base_app, *, return_to: str, final_redirect: str) -> str:
    """Return the exact GET URL `requests` builds for silent login."""
    silent = base_app.config["SSO_BROKER_SILENT_LOGIN_URL"]
    preq = requests.Request(
        "GET",
        silent,
        params={"return_to": return_to, "final_redirect": final_redirect},
    ).prepare()
    return preq.url


@pytest.mark.usefixtures("base_app")
class TestSessionBrokerSilentLoginCheck:
    """Green-path and light contract tests for `silent_login_check`."""

    def test_silent_login_returns_json_when_broker_token_present(
        self, base_app, requests_mock
    ):
        """Broker returns 200 with `broker_token`; client returns that dict."""
        return_to = "http://localhost/works/callback"
        final_redirect = "http://localhost/works/"
        url = _silent_login_prepared_url(
            base_app, return_to=return_to, final_redirect=final_redirect
        )
        payload = {"broker_token": "broker-jwt", "session_id": "sid-1"}
        requests_mock.get(url, json=payload)
        cookies = {"_sso_checked": "cookie-val", "other": "ignored"}
        with base_app.app_context():
            out = SessionBrokerAPIClient.silent_login_check(
                cookies,
                return_to=return_to,
                final_redirect=final_redirect,
            )
        assert out == payload
        assert len(requests_mock.request_history) == 1
        req = requests_mock.last_request
        assert req is not None
        assert req.method == "GET"
        assert req.url == url
        token = os.environ["COMMONS_PROFILES_API_TOKEN"]
        assert req.headers.get("Authorization") == f"Bearer {token}"
        cookie_header = req.headers.get("Cookie") or ""
        assert "_sso_checked=cookie-val" in cookie_header

    def test_silent_login_returns_none_when_no_session(self, base_app, requests_mock):
        """Broker signals no active session; client returns `None` without raising."""
        return_to = "http://localhost/r"
        final_redirect = "http://localhost/f"
        url = _silent_login_prepared_url(
            base_app, return_to=return_to, final_redirect=final_redirect
        )
        requests_mock.get(url, json={"no_session": True})
        with base_app.app_context():
            out = SessionBrokerAPIClient.silent_login_check(
                {},
                return_to=return_to,
                final_redirect=final_redirect,
            )
        assert out is None
        assert len(requests_mock.request_history) == 1

    def test_silent_login_transport_failure_returns_none_and_logs(
        self, base_app, requests_mock, caplog
    ):
        """Network failure is swallowed; exception is logged once."""
        return_to = "http://localhost/r"
        final_redirect = "http://localhost/f"
        url = _silent_login_prepared_url(
            base_app, return_to=return_to, final_redirect=final_redirect
        )
        requests_mock.get(url, exc=requests.ConnectionError("refused"))
        with caplog.at_level(logging.ERROR):
            with base_app.app_context():
                out = SessionBrokerAPIClient.silent_login_check(
                    {},
                    return_to=return_to,
                    final_redirect=final_redirect,
                )
        assert out is None
        assert "Silent login check failed" in _caplog_messages(caplog)

    def test_silent_login_no_http_when_silent_url_missing(
        self, base_app, requests_mock
    ):
        """Missing silent-login URL → `None`, no outbound request."""
        saved = base_app.config["SSO_BROKER_SILENT_LOGIN_URL"]
        base_app.config["SSO_BROKER_SILENT_LOGIN_URL"] = ""
        try:
            with base_app.app_context():
                out = SessionBrokerAPIClient.silent_login_check(
                    {},
                    return_to="http://localhost/r",
                    final_redirect="http://localhost/f",
                )
            assert out is None
            assert len(requests_mock.request_history) == 0
        finally:
            base_app.config["SSO_BROKER_SILENT_LOGIN_URL"] = saved

    def test_silent_login_no_http_when_token_missing(
        self, base_app, requests_mock, monkeypatch
    ):
        """Missing bearer token → `None`, no outbound request."""
        monkeypatch.delenv("COMMONS_PROFILES_API_TOKEN", raising=False)
        with base_app.app_context():
            out = SessionBrokerAPIClient.silent_login_check(
                {},
                return_to="http://localhost/r",
                final_redirect="http://localhost/f",
            )
        assert out is None
        assert len(requests_mock.request_history) == 0

    def test_silent_login_none_on_http_401(self, base_app, requests_mock, caplog):
        """Non-2xx from broker → `None` and exception log."""
        return_to = "http://localhost/r"
        final_redirect = "http://localhost/f"
        url = _silent_login_prepared_url(
            base_app, return_to=return_to, final_redirect=final_redirect
        )
        requests_mock.get(url, status_code=401, text="no")
        with caplog.at_level(logging.ERROR):
            with base_app.app_context():
                out = SessionBrokerAPIClient.silent_login_check(
                    {},
                    return_to=return_to,
                    final_redirect=final_redirect,
                )
        assert out is None
        assert "Silent login check failed" in _caplog_messages(caplog)

    def test_silent_login_none_when_json_has_no_broker_token(
        self, base_app, requests_mock
    ):
        """200 without `broker_token` → `None` (shape guard)."""
        return_to = "http://localhost/r"
        final_redirect = "http://localhost/f"
        url = _silent_login_prepared_url(
            base_app, return_to=return_to, final_redirect=final_redirect
        )
        requests_mock.get(url, json={"hello": "world"})
        with base_app.app_context():
            out = SessionBrokerAPIClient.silent_login_check(
                {},
                return_to=return_to,
                final_redirect=final_redirect,
            )
        assert out is None
        assert len(requests_mock.request_history) == 1


@pytest.mark.usefixtures("base_app")
class TestSessionBrokerVerifyNonce:
    """Green-path and light contract tests for `verify_nonce`."""

    def test_verify_nonce_true_when_profiles_returns_valid(
        self, base_app, requests_mock
    ):
        """POST JSON `nonce`; 200 with `"valid": true` → `True`."""
        verify_url = base_app.config["SSO_BROKER_VERIFY_NONCE_URL"]
        nonce = "nonce-abc-123"
        requests_mock.post(verify_url, json={"valid": True})
        with base_app.app_context():
            ok = SessionBrokerAPIClient.verify_nonce(nonce)
        assert ok is True
        assert len(requests_mock.request_history) == 1
        req = requests_mock.last_request
        assert req is not None
        assert req.method == "POST"
        assert req.url == verify_url
        token = os.environ["COMMONS_PROFILES_API_TOKEN"]
        assert req.headers.get("Authorization") == f"Bearer {token}"
        assert req.headers.get("Content-Type") == "application/json"
        body = json.loads(req.body.decode())
        assert body == {"nonce": nonce}

    def test_verify_nonce_false_when_profiles_returns_valid_false(
        self, base_app, requests_mock
    ):
        """Explicit `"valid": false` → `False` (no exception)."""
        verify_url = base_app.config["SSO_BROKER_VERIFY_NONCE_URL"]
        requests_mock.post(verify_url, json={"valid": False})
        with base_app.app_context():
            ok = SessionBrokerAPIClient.verify_nonce("n1")
        assert ok is False

    def test_verify_nonce_transport_failure_returns_false_and_logs(
        self, base_app, requests_mock, caplog
    ):
        """Network failure → `False` and exception log (same pattern as silent)."""
        verify_url = base_app.config["SSO_BROKER_VERIFY_NONCE_URL"]
        requests_mock.post(verify_url, exc=requests.Timeout("slow"))
        with caplog.at_level(logging.ERROR):
            with base_app.app_context():
                ok = SessionBrokerAPIClient.verify_nonce("n2")
        assert ok is False
        assert "Nonce verification request failed" in _caplog_messages(caplog)

    def test_verify_nonce_false_when_verify_url_missing(
        self, base_app, requests_mock
    ):
        """Missing verify URL → `False`, no POST."""
        saved = base_app.config["SSO_BROKER_VERIFY_NONCE_URL"]
        base_app.config["SSO_BROKER_VERIFY_NONCE_URL"] = ""
        try:
            with base_app.app_context():
                ok = SessionBrokerAPIClient.verify_nonce("any")
            assert ok is False
            assert len(requests_mock.request_history) == 0
        finally:
            base_app.config["SSO_BROKER_VERIFY_NONCE_URL"] = saved

    def test_verify_nonce_false_when_token_missing(
        self, base_app, requests_mock, monkeypatch
    ):
        """Missing bearer token → `False`, no POST."""
        monkeypatch.delenv("COMMONS_PROFILES_API_TOKEN", raising=False)
        with base_app.app_context():
            ok = SessionBrokerAPIClient.verify_nonce("any")
        assert ok is False
        assert len(requests_mock.request_history) == 0

    def test_verify_nonce_false_on_http_503(self, base_app, requests_mock, caplog):
        """Non-2xx from broker → `False` and exception log."""
        verify_url = base_app.config["SSO_BROKER_VERIFY_NONCE_URL"]
        requests_mock.post(verify_url, status_code=503, text="busy")
        with caplog.at_level(logging.ERROR):
            with base_app.app_context():
                ok = SessionBrokerAPIClient.verify_nonce("n3")
        assert ok is False
        assert "Nonce verification request failed" in _caplog_messages(caplog)
