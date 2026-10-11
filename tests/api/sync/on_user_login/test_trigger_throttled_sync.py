# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""Login triggers a remote user-data sync, gated by the session throttle.

When someone logs into KCWorks, we may pull a fresh Profiles record for them.
That work is enqueued as `do_user_data_update` with no status callback back to
Profiles. A short per-browser session window
(`REMOTE_USER_DATA_UPDATE_INTERVAL`) stops us from enqueueing again on every
login in that window — including when the Profiles broker already synced (or
enqueued) and stamped the session before `login_user` fires.

Covers:

- A login with no recent sync stamp enqueues
  `do_user_data_update.delay(user_id, send_status_callback=False)`.
- A second login inside the update interval does not enqueue again and does
  not call Profiles again.
- After broker login sync (inline, or enqueue when the per-user update lock is
  busy), the session is stamped so the following `login_user` does not enqueue
  a second update or hit Profiles again.
- When a due login sync actually runs, Profiles is contacted once via the
  subs endpoint; the members endpoint is unused on this path.

Related coverage elsewhere:

- Applying remote fields onto the local account after that sync →
  `test_e2e_apply_from_login.py`.
- Rewriting `kc_username` on published/draft records after a rename →
  `on_username_changed/test_e2e_from_login.py`.
- Request identity / group principals after login →
  `test_identity_after_login.py` in this folder.
- Broker token crypto, redirects, and silent SSO checks → `ui/sso/`.
"""

from unittest.mock import MagicMock, patch

from flask_login import login_user

from invenio_remote_user_data_kcworks.utils.broker import BrokerHelpers
from tests.fixtures.users import user_data_set


def test_login_enqueues_user_data_update_when_due(
    running_app,
    db,
    user_factory,
    search_clear,
    mock_send_remote_api_update_fixture,
):
    """Due login enqueues do_user_data_update with send_status_callback=False."""
    new_data_payload = user_data_set["user1"]
    u = user_factory(
        email="originalemail@kcommons.org",
        oauth_src="cilogon",
        oauth_id=new_data_payload["oauth_id"],
        kc_username="beforesync",
        new_remote_data=new_data_payload,
    )

    with patch(
        "invenio_remote_user_data_kcworks.ext.do_user_data_update",
    ) as do_update:
        login_user(u.user)
        do_update.delay.assert_called_once_with(
            u.user.id,
            send_status_callback=False,
        )


def test_second_login_within_interval_does_not_enqueue(
    running_app,
    db,
    user_factory,
    search_clear,
    mock_send_remote_api_update_fixture,
):
    """Second login inside UPDATE_INTERVAL does not enqueue again."""
    new_data_payload = user_data_set["user1"]
    u = user_factory(
        email="originalemail@kcommons.org",
        oauth_src="cilogon",
        oauth_id=new_data_payload["oauth_id"],
        kc_username="beforesync",
        new_remote_data=new_data_payload,
    )

    with patch(
        "invenio_remote_user_data_kcworks.ext.do_user_data_update",
    ) as do_update:
        login_user(u.user)
        login_user(u.user)
        do_update.delay.assert_called_once_with(
            u.user.id,
            send_status_callback=False,
        )


def test_due_login_sync_hits_profiles_subs_once(
    running_app,
    db,
    user_factory,
    search_clear,
    celery_worker,
    mock_send_remote_api_update_fixture,
):
    """Due login sync runs the task and contacts Profiles subs once."""
    new_data_payload = user_data_set["user1"]
    u = user_factory(
        email="originalemail@kcommons.org",
        oauth_src="cilogon",
        oauth_id=new_data_payload["oauth_id"],
        kc_username="beforesync",
        new_remote_data=new_data_payload,
    )

    for mock_adapter in u.mock_adapter_subs, u.mock_adapter_members:
        assert not mock_adapter.called
        assert mock_adapter.call_count == 0

    login_user(u.user)

    assert u.mock_adapter_subs.called
    assert u.mock_adapter_subs.call_count == 1
    assert not u.mock_adapter_members.called
    assert u.mock_adapter_members.call_count == 0


def test_second_login_within_interval_does_not_call_profiles_again(
    running_app,
    db,
    user_factory,
    search_clear,
    celery_worker,
    mock_send_remote_api_update_fixture,
):
    """Second login inside the interval does not hit Profiles again."""
    new_data_payload = user_data_set["user1"]
    u = user_factory(
        email="originalemail@kcommons.org",
        oauth_src="cilogon",
        oauth_id=new_data_payload["oauth_id"],
        kc_username="beforesync",
        new_remote_data=new_data_payload,
    )

    login_user(u.user)
    assert u.mock_adapter_subs.call_count == 1

    login_user(u.user)
    assert u.mock_adapter_subs.call_count == 1
    assert u.mock_adapter_members.call_count == 0


def test_broker_inline_sync_stamp_prevents_login_enqueue(
    running_app,
    db,
    user_factory,
    search_clear,
    mock_send_remote_api_update_fixture,
):
    """Broker inline sync stamps the session; login_user does not enqueue."""
    app = running_app.app
    new_data_payload = user_data_set["user1"]
    u = user_factory(
        email="originalemail@kcommons.org",
        oauth_src="cilogon",
        oauth_id=new_data_payload["oauth_id"],
        kc_username="beforesync",
        new_remote_data=new_data_payload,
    )
    app.config["REMOTE_USER_DATA_UPDATE_LOCK_ENABLED"] = False

    with (
        patch(
            "invenio_remote_user_data_kcworks.utils.broker."
            "current_remote_user_data_service.update_user_from_remote",
        ),
        patch(
            "invenio_remote_user_data_kcworks.utils.broker.sync_user_to_names",
        ),
    ):
        BrokerHelpers()._sync_user_data_after_broker_login(
            u.user,
            new_data_payload["oauth_id"],
            None,
        )

    with patch(
        "invenio_remote_user_data_kcworks.ext.do_user_data_update",
    ) as do_update:
        login_user(u.user)
        do_update.delay.assert_not_called()


def test_broker_lock_busy_enqueue_stamp_prevents_login_enqueue(
    running_app,
    db,
    user_factory,
    search_clear,
    mock_send_remote_api_update_fixture,
):
    """Lock-busy broker path enqueues + stamps; login_user does not enqueue."""
    app = running_app.app
    new_data_payload = user_data_set["user1"]
    u = user_factory(
        email="originalemail@kcommons.org",
        oauth_src="cilogon",
        oauth_id=new_data_payload["oauth_id"],
        kc_username="beforesync",
        new_remote_data=new_data_payload,
    )
    app.config["REMOTE_USER_DATA_UPDATE_LOCK_ENABLED"] = True

    waiting_lock = MagicMock()
    waiting_lock.status = "waiting"
    waiting_lock.acquire = MagicMock()

    with (
        patch(
            "invenio_remote_user_data_kcworks.utils.broker.UserUpdateLock",
            return_value=waiting_lock,
        ),
        patch(
            "invenio_remote_user_data_kcworks.utils.broker.do_user_data_update",
        ) as broker_update,
    ):
        BrokerHelpers()._sync_user_data_after_broker_login(
            u.user,
            new_data_payload["oauth_id"],
            None,
        )
        broker_update.delay.assert_called_once_with(
            u.user.id,
            "knowledgeCommons",
            remote_id=new_data_payload["oauth_id"],
            send_status_callback=False,
        )

    with patch(
        "invenio_remote_user_data_kcworks.ext.do_user_data_update",
    ) as do_update:
        login_user(u.user)
        do_update.delay.assert_not_called()
