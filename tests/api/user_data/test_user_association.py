# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Tests for CILogon association webhook handling and background tasks."""

import json
from unittest.mock import patch

from flask import url_for
from invenio_accounts.models import UserIdentity
from invenio_accounts.proxies import current_accounts

from invenio_remote_user_data_kcworks.client import UserDataAPIClient
from invenio_remote_user_data_kcworks.config import UserDataEvent, UserDataStatus
from invenio_remote_user_data_kcworks.tasks import do_user_associated
from invenio_remote_user_data_kcworks.views import _normalize_webhook_payload
from tests.fixtures.association import ASSOCIATION_OAUTH_ID, association_webhook_payload
from tests.fixtures.users import user_data_set


def test_normalize_webhook_payload_associations():
    """Top-level associations payloads are normalized to updates.associations."""
    payload = association_webhook_payload("djfader", nested=True)
    normalized = _normalize_webhook_payload(payload)
    assert normalized["updates"] == {
        "associations": [
            {
                "id": ASSOCIATION_OAUTH_ID,
                "kc_id": "djfader",
                "event": "associated",
            }
        ]
    }


def test_do_user_associated_links_identity_and_syncs(
    running_app,
    db,
    user_factory,
    requests_mock,
    search_clear,
    user_data_to_remote_data,
):
    """Association task links CILogon identity and syncs profile from Profiles API."""
    app = running_app.app
    profile_data = user_data_set["user1"]
    base_url = app.config["IDMS_BASE_API_URL"]
    _subs_payload, members_payload, _ = user_data_to_remote_data(
        kc_username=profile_data["kc_username"],
        email=profile_data["email"],
        user_data=profile_data,
        oauth_id=ASSOCIATION_OAUTH_ID,
    )
    members_mock = requests_mock.get(
        f"{base_url}members/{profile_data['kc_username']}/",
        json=members_payload,
    )

    u = user_factory(
        email=profile_data["email"],
        kc_username=profile_data["kc_username"],
        oauth_src=None,
        oauth_id=None,
        new_remote_data={},
    )
    user_id = u.user.id
    assert (
        UserIdentity.query.filter_by(
            id_user=user_id, method="cilogon", id=ASSOCIATION_OAUTH_ID
        ).first()
        is None
    )

    result = do_user_associated(
        user_id,
        "knowledgeCommons",
        oauth_id=ASSOCIATION_OAUTH_ID,
        auth_method="cilogon",
        kc_username=profile_data["kc_username"],
    )

    assert result["status"] == "associated"
    assert members_mock.called
    identity = UserIdentity.query.filter_by(
        id_user=user_id, method="cilogon", id=ASSOCIATION_OAUTH_ID
    ).one()
    assert identity.id_user == user_id

    synced = current_accounts.datastore.get_user_by_id(user_id)
    assert synced.user_profile.get("full_name") == profile_data["name"]
    assert (
        synced.user_profile.get("identifier_kc_username") == profile_data["kc_username"]
    )


@patch.object(UserDataAPIClient, "send_user_status_callback", return_value=True)
def test_do_user_associated_sends_processed_callback(
    mock_send_status,
    running_app,
    db,
    user_factory,
    requests_mock,
    search_clear,
    user_data_to_remote_data,
):
    """Successful association notifies Profiles with event=associated."""
    app = running_app.app
    profile_data = user_data_set["user1"]
    base_url = app.config["IDMS_BASE_API_URL"]
    _subs_payload, members_payload, _ = user_data_to_remote_data(
        kc_username=profile_data["kc_username"],
        email=profile_data["email"],
        user_data=profile_data,
        oauth_id=ASSOCIATION_OAUTH_ID,
    )
    requests_mock.get(
        f"{base_url}members/{profile_data['kc_username']}/",
        json=members_payload,
    )

    u = user_factory(
        email=profile_data["email"],
        kc_username=profile_data["kc_username"],
        oauth_src=None,
        oauth_id=None,
        new_remote_data={},
    )
    user_id = u.user.id

    result = do_user_associated(
        user_id,
        "knowledgeCommons",
        oauth_id=ASSOCIATION_OAUTH_ID,
        auth_method="cilogon",
        kc_username=profile_data["kc_username"],
    )

    assert result["status"] == "associated"
    mock_send_status.assert_called_once()
    assert mock_send_status.call_args.kwargs["status"] == UserDataStatus.PROCESSED
    assert mock_send_status.call_args.kwargs["event"] == UserDataEvent.ASSOCIATED
    assert mock_send_status.call_args.kwargs["sub"] == ASSOCIATION_OAUTH_ID
    assert mock_send_status.call_args.kwargs["username"] == profile_data["kc_username"]


@patch.object(UserDataAPIClient, "send_user_status_callback", return_value=True)
def test_do_user_associated_sends_failed_callback_when_oauth_linked_elsewhere(
    mock_send_status,
    running_app,
    db,
    user_factory,
    search_clear,
):
    """Association conflict notifies Profiles with FAILED and event=associated."""
    owner_data = user_data_set["user1"]
    other_data = user_data_set["user2"]

    owner = user_factory(
        email=owner_data["email"],
        kc_username=owner_data["kc_username"],
        oauth_src=None,
        oauth_id=None,
        new_remote_data={},
    )
    other = user_factory(
        email=other_data["email"],
        kc_username=other_data["kc_username"],
        oauth_src=None,
        oauth_id=None,
        new_remote_data={},
    )
    owner_user = current_accounts.datastore.get_user_by_id(owner.user.id)
    UserIdentity.create(owner_user, "cilogon", ASSOCIATION_OAUTH_ID)
    db.session.commit()

    result = do_user_associated(
        other.user.id,
        "knowledgeCommons",
        oauth_id=ASSOCIATION_OAUTH_ID,
        auth_method="cilogon",
        kc_username=other_data["kc_username"],
    )

    assert result["status"] == "error"
    mock_send_status.assert_called_once()
    assert mock_send_status.call_args.kwargs["status"] == UserDataStatus.FAILED
    assert mock_send_status.call_args.kwargs["event"] == UserDataEvent.ASSOCIATED
    assert "oauth_identity_linked_to_other_user" in (
        mock_send_status.call_args.kwargs.get("note") or ""
    )


@patch.object(UserDataAPIClient, "send_user_status_callback", return_value=True)
def test_do_user_associated_sends_failed_callback_when_user_missing(
    mock_send_status,
    running_app,
    db,
):
    """Missing local user notifies Profiles with FAILED before returning."""
    result = do_user_associated(
        999_999,
        "knowledgeCommons",
        oauth_id=ASSOCIATION_OAUTH_ID,
        auth_method="cilogon",
        kc_username="ghost-user",
    )

    assert result["status"] == "error"
    mock_send_status.assert_called_once()
    assert mock_send_status.call_args.kwargs["status"] == UserDataStatus.FAILED
    assert mock_send_status.call_args.kwargs["event"] == UserDataEvent.ASSOCIATED
    assert mock_send_status.call_args.kwargs["note"] == "user_not_found"


def test_do_user_associated_is_idempotent_when_already_linked(
    running_app,
    db,
    user_factory,
    requests_mock,
    search_clear,
    user_data_to_remote_data,
):
    """Re-running association for the same user and OAuth id is a no-op link."""
    app = running_app.app
    profile_data = user_data_set["user1"]
    base_url = app.config["IDMS_BASE_API_URL"]
    _subs_payload, members_payload, _ = user_data_to_remote_data(
        kc_username=profile_data["kc_username"],
        email=profile_data["email"],
        user_data=profile_data,
        oauth_id=ASSOCIATION_OAUTH_ID,
    )
    requests_mock.get(
        f"{base_url}members/{profile_data['kc_username']}/",
        json=members_payload,
    )

    u = user_factory(
        email=profile_data["email"],
        kc_username=profile_data["kc_username"],
        oauth_src=None,
        oauth_id=None,
        new_remote_data={},
    )
    user_id = u.user.id
    user = current_accounts.datastore.get_user_by_id(user_id)
    UserIdentity.create(user, "cilogon", ASSOCIATION_OAUTH_ID)
    db.session.commit()

    do_user_associated(
        user_id,
        "knowledgeCommons",
        oauth_id=ASSOCIATION_OAUTH_ID,
        auth_method="cilogon",
        kc_username=profile_data["kc_username"],
    )

    identities = UserIdentity.query.filter_by(
        method="cilogon", id=ASSOCIATION_OAUTH_ID
    ).all()
    assert len(identities) == 1
    assert identities[0].id_user == user_id


def test_do_user_associated_rejects_oauth_id_linked_to_other_user(
    running_app, db, user_factory, search_clear
):
    """Association fails when the OAuth id already belongs to another user."""
    owner_data = user_data_set["user1"]
    other_data = user_data_set["user2"]

    owner = user_factory(
        email=owner_data["email"],
        kc_username=owner_data["kc_username"],
        oauth_src=None,
        oauth_id=None,
        new_remote_data={},
    )
    owner_id = owner.user.id
    other = user_factory(
        email=other_data["email"],
        kc_username=other_data["kc_username"],
        oauth_src=None,
        oauth_id=None,
        new_remote_data={},
    )
    other_id = other.user.id
    owner_user = current_accounts.datastore.get_user_by_id(owner_id)
    UserIdentity.create(owner_user, "cilogon", ASSOCIATION_OAUTH_ID)
    db.session.commit()

    result = do_user_associated(
        other_id,
        "knowledgeCommons",
        oauth_id=ASSOCIATION_OAUTH_ID,
        auth_method="cilogon",
        kc_username=other_data["kc_username"],
    )

    assert result["status"] == "error"
    assert result["reason"] == "OAuth identity already linked to another user"
    assert (
        UserIdentity.query.filter_by(
            id_user=other_id, method="cilogon", id=ASSOCIATION_OAUTH_ID
        ).first()
        is None
    )


def test_association_webhook_unknown_user_returns_not_found(
    app,
    client,
    headers,
    idms_static_api_auth,
):
    """Association webhook returns 404 when the KC user is not known locally."""
    with (
        patch("invenio_accounts.utils.current_user"),
        app.app_context(),
    ):
        url = url_for(
            "invenio_remote_user_data_kcworks.remote_user_data_kcworks_webhook",
        )
        response = client.post(
            url,
            json=association_webhook_payload("unknown-kc-user"),
            headers={**headers, **idms_static_api_auth},
        )

    assert response.status_code == 404
    assert "unknown" in response.get_json()["message"].lower()


def test_user_association_sync_on_webhook(
    running_app,
    db,
    user_factory,
    client,
    requests_mock,
    headers,
    search_clear,
    celery_worker,
    mock_send_remote_api_update_fixture,
    user_data_to_remote_data,
    idms_static_api_auth,
):
    """Webhook links CILogon identity and syncs profile from Profiles API."""
    app = running_app.app
    profile_data = user_data_set["user1"]

    u = user_factory(
        email=profile_data["email"],
        kc_username=profile_data["kc_username"],
        oauth_src=None,
        oauth_id=None,
        new_remote_data={},
    )
    user_id = u.user.id
    user = current_accounts.datastore.get_user_by_id(user_id)
    UserIdentity.create(user, "knowledgeCommons", profile_data["kc_username"])
    db.session.commit()

    assert (
        UserIdentity.query.filter_by(
            id_user=user_id, method="cilogon", id=ASSOCIATION_OAUTH_ID
        ).first()
        is None
    )

    base_url = app.config.get("IDMS_BASE_API_URL")
    _mock_remote_data_subs, mock_remote_data_members, _ = user_data_to_remote_data(
        kc_username=profile_data["kc_username"],
        email=profile_data["email"],
        user_data=profile_data,
        oauth_id=ASSOCIATION_OAUTH_ID,
    )
    mock_adapter_members = requests_mock.get(
        f"{base_url}members/{profile_data['kc_username']}/",
        json=mock_remote_data_members,
    )

    with patch("invenio_accounts.utils.current_user"):
        with app.app_context():
            post_url = url_for(
                "invenio_remote_user_data_kcworks.remote_user_data_kcworks_webhook",
            )
        response = client.post(
            post_url,
            json=association_webhook_payload(profile_data["kc_username"]),
            headers={**headers, **idms_static_api_auth},
        )

    assert response.status_code == 202
    assert response.json == {
        "message": "Webhook notification accepted",
        "status": 202,
        "updates": {
            "associations": [
                {
                    "id": ASSOCIATION_OAUTH_ID,
                    "kc_id": profile_data["kc_username"],
                    "event": "associated",
                }
            ]
        },
    }
    assert mock_adapter_members.called
    assert mock_adapter_members.call_count == 1

    user = current_accounts.datastore.get_user_by_id(user_id)
    cilogon_identity = UserIdentity.query.filter_by(
        id_user=user_id, method="cilogon", id=ASSOCIATION_OAUTH_ID
    ).one()
    assert cilogon_identity.id_user == user_id

    assert user.email == profile_data["email"]
    assert user.user_profile.get("full_name") == profile_data["name"]
    assert (
        user.user_profile.get("identifier_kc_username") == profile_data["kc_username"]
    )
    assert user.user_profile.get("identifier_orcid") == profile_data["orcid"]
    assert json.loads(user.user_profile.get("name_parts")) == {
        "first": profile_data["first_name"],
        "last": profile_data["last_name"],
    }
    assert sorted(r.name for r in user.roles) == sorted([
        "knowledgeCommons---12345|administrator",
        "knowledgeCommons---67891|member",
    ])
