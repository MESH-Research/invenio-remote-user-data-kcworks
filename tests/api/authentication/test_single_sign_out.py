# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""Tests of the webhook signal receiving for single-sign-out with KC."""

from flask import url_for
from flask_security import login_user
from invenio_accounts.models import SessionActivity
from invenio_accounts.testutils import login_user_via_session


def test_logout_webhook_get_ping(app, client):
    """GET confirms the receiver is mounted (no username processing)."""
    webhook_url = url_for(
        "invenio_remote_user_data_kcworks.remote_user_data_kcworks_logout_webhook",
    )
    resp = client.get(webhook_url)
    assert resp.status_code == 200
    assert resp.json == {"message": "Webhook receiver is active", "status": 200}


def test_logout_webhook_post_requires_username(
    app, client, db, idms_static_api_auth
):
    """POST without ``username`` query param returns 400."""
    webhook_url = url_for(
        "invenio_remote_user_data_kcworks.remote_user_data_kcworks_logout_webhook",
    )
    resp = client.post(
        webhook_url,
        headers=idms_static_api_auth,
    )
    assert resp.status_code == 400


def test_logout_webhook_post_unknown_username_returns_404(
    app, client, idms_static_api_auth
):
    """Central logout for a KC username that does not exist locally → 404 JSON."""
    webhook_url = url_for(
        "invenio_remote_user_data_kcworks.remote_user_data_kcworks_logout_webhook",
    )
    resp = client.post(
        webhook_url,
        query_string={"username": "definitely_missing_user"},
        headers=idms_static_api_auth,
    )
    assert resp.status_code == 404
    body = resp.json
    assert body["status"] == "not found"
    assert "not found" in body["message"].lower()


def test_logout_webhook_post_invalidates_sessions(
    app, db, client, admin, user_factory, idms_static_api_auth
):
    """Inbound webhook deletes sessions for every local user matched by KC username."""
    webhook_url = url_for(
        "invenio_remote_user_data_kcworks.remote_user_data_kcworks_logout_webhook",
    )
    kc_username = "sso_signout_user"
    u = user_factory(
        email="sso-signout@example.com",
        oauth_src="cilogon",
        oauth_id="http://cilogon.org/serverE/users/99999",
        kc_username=kc_username,
        new_remote_data={"name": "SSO Signout"},
    )
    user = u.user
    db.session.commit()
    login_user(user)
    login_user_via_session(client, email=user.email)

    # ``login_user_via_session`` only sets ``user_id`` on the KV session; it does not
    # insert ``SessionActivity``. ``delete_user_sessions`` removes KV keys listed in
    # ``user.active_sessions`` (that table), so without a row nothing is deleted.
    with client.session_transaction() as sess:
        sid_s = sess.sid_s
    assert sid_s is not None
    db.session.merge(SessionActivity(user_id=user.id, sid_s=sid_s, ip="127.0.0.1"))
    db.session.commit()

    # Call the webhook from a client with no session cookies (like production:
    # KC sends only the static Bearer). If the same client POSTs with the
    # victim's cookie, Flask-KVSession can re-save that session at end of
    # request after delete_user_sessions removed it from the store.
    with app.test_client() as webhook_client:
        resp = webhook_client.post(
            webhook_url,
            query_string={"username": kc_username},
            headers=idms_static_api_auth,
        )
    assert resp.status_code == 200
    assert resp.json["status"] == "success"

    # After deletion the cookie sid is gone from the KV store; next load is empty.
    with client.session_transaction() as sess:
        assert sess.get("user_id") in (None, "")
        assert sess.get("_user_id") in (None, "")
