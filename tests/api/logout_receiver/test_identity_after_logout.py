# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""Request identity after local logout (session cleared).

Covers:

- After local logout + session cleared, `g.identity` is only `any_user`
  (not the central logout webhook).

Central logout webhook: `test_inbound_webhook.py`.
Local UI logout → Profiles: `ui/logout/`.
"""

import time

from flask import g
from flask_login import login_user, logout_user
from invenio_accounts.testutils import login_user_via_session

from tests.fixtures.users import user_data_set


def test_identity_after_local_logout_is_only_any_user(
    running_app,
    db,
    client,
    user_factory,
    search_clear,
    celery_worker,
    mock_send_remote_api_update_fixture,
    mock_logout_signal_receiver,
):
    """After local logout and session clear, identity is only any_user."""
    new_data_payload = user_data_set["user1"]
    kc_username = "beforesync"
    u1_fixture = user_factory(
        email="originalemail@kcommons.org",
        oauth_src="cilogon",
        oauth_id=new_data_payload["oauth_id"],
        kc_username=kc_username,
        new_remote_data=new_data_payload,
    )
    myuser1 = u1_fixture.user

    assert login_user(myuser1)
    login_user_via_session(client, user=myuser1)
    client.get("/api")

    # Local logout posts to Profiles ``actions/logout/``; mock that hop.
    mock_logout_signal_receiver(kc_username)
    logout_user()
    with client.session_transaction() as session:
        if "user_id" in session:
            del session["user_id"]
            del session["_user_id"]
    time.sleep(10)
    client.get("/api")
    my_identity = g.identity
    assert len([n.value for n in my_identity.provides if n.value in ["any_user"]]) == 1
    assert (
        len([n.value for n in my_identity.provides if n.value not in ["any_user"]]) == 0
    )
