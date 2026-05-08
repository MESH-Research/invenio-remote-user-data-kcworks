# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""Tests of the signal emission for single-sign-out with KC."""

import json

from flask_security import login_user, logout_user
from invenio_accounts.testutils import login_user_via_session


def test_local_logout_posts_to_profiles_actions_logout(
    app,
    client,
    user_factory,
    db,
    requests_mock,
    mock_logout_signal_receiver,
    monkeypatch,
):
    """Local `logout_user` triggers POST to Profiles `actions/logout/` with body."""
    token = "test-profiles-api-token"
    monkeypatch.setenv("COMMONS_PROFILES_API_TOKEN", token)
    kc_username = "local_logout_kc_user"
    mock_logout_signal_receiver(kc_username)
    u = user_factory(
        email="local-logout@example.com",
        oauth_src="cilogon",
        oauth_id="http://cilogon.org/serverE/users/88888",
        kc_username=kc_username,
        new_remote_data={"name": "Local Logout"},
    )
    user = u.user
    db.session.commit()
    login_user(user)
    login_user_via_session(client, email=user.email)
    logout_user()
    base = app.config["IDMS_BASE_API_URL"].rstrip("/")
    post = next(
        h
        for h in requests_mock.request_history
        if h.method == "POST" and h.url.startswith(base) and "actions/logout" in h.url
    )
    sent = json.loads(post.body.decode("utf-8")) if post.body else {}
    assert sent.get("user_name") == kc_username
    assert "user_agent" in sent
    assert post.headers.get("Authorization") == f"Bearer {token}"


def test_local_logout_falls_back_to_username_prefix_when_no_kc_profile_key(
    app,
    client,
    user_factory,
    db,
    requests_mock,
    mock_logout_signal_receiver,
    monkeypatch,
):
    """Assert logout strips `knowledgeCommons-` when profile has no KC username.

    If `user_profile` has no `identifier_kc_username`, the handler must strip the
    `knowledgeCommons-` prefix from `user.username` and pass that value in the
    Profiles `actions/logout/` request body as `user_name`.

    `user_factory` is invoked with `kc_username=None` because its default would
    set `identifier_kc_username` to `myuser` and skip this fallback path.
    """
    token = "test-profiles-api-token"
    monkeypatch.setenv("COMMONS_PROFILES_API_TOKEN", token)
    remote_name = "fallback_user"
    mock_logout_signal_receiver(remote_name)
    # Default `kc_username` on `user_factory` is `myuser`, which would set
    # `identifier_kc_username` and defeat this fallback path.
    u = user_factory(email="fallback-logout@example.com", kc_username=None)
    user = u.user
    user.username = f"knowledgeCommons-{remote_name}"
    db.session.add(user)
    db.session.commit()
    login_user(user)
    login_user_via_session(client, email=user.email)
    logout_user()
    post = next(
        h
        for h in requests_mock.request_history
        if h.method == "POST" and "actions/logout" in h.url
    )
    sent = json.loads(post.body.decode("utf-8"))
    assert sent["user_name"] == remote_name
    assert post.headers.get("Authorization") == f"Bearer {token}"
