"""Webhook view tests for remote user-data endpoints."""

import json

import pytest
from flask import url_for
from invenio_accounts.proxies import current_accounts

from invenio_remote_user_data_kcworks.services.group_roles import GroupRolesService
from invenio_remote_user_data_kcworks.services.service import RemoteUserDataService


def test_webhook_get(client, app, search_clear):
    """Test webhook."""
    response = client.get(
        url_for(
            "invenio_remote_user_data_kcworks.remote_user_data_kcworks_webhook",
        )
    )

    assert response.status_code == 200
    assert json.loads(response.data) == {
        "message": "Webhook receiver is active",
        "status": 200,
    }


@pytest.mark.parametrize(
    "payload,callback_responses,resp_code,resp_data",
    [
        (
            {
                "idp": "knowledgeCommons",
                "updates": {
                    "users": [
                        {"id": "1234", "event": "updated"},
                        {"id": "5678", "event": "created"},
                    ],
                    "groups": [{"id": "1234", "event": "deleted"}],
                },
            },
            {},
            403,
            {
                "error": "Forbidden",
                "message": (
                    "The user does not have permission to perform this action."
                ),
                "status": 403,
            },
        ),
        (
            {
                "idp": "knowledgeCommons",
                "updates": {
                    "users": [
                        {"id": "joeuser", "event": "updated"},
                        # {"id": "5678", "event": "created"},
                    ],
                    # "groups": [{"id": "1234", "event": "deleted"}],
                },
            },
            {
                "users": [
                    {
                        "username": "joeuser",
                        "email": "joeuser@hcommons.org",
                        "name": "Joe User",
                        "first_name": "Joe",
                        "last_name": "User",
                        "institutional_affiliation": ("Michigan State University"),
                        "orcid": "0000-0002-1825-0097",
                        "groups": [
                            {
                                "id": 1000551,
                                "name": "Digital Humanists",
                                "role": "member",
                            },
                            {
                                "id": 1000576,
                                "name": "test bpges",
                                "role": "admin",
                            },
                        ],
                    },
                ],
            },
            202,
            {
                "message": "Webhook notification accepted",
                "status": 202,
                "updates": {
                    # "groups": [{"id": "1234", "event": "deleted"}],
                    "users": [
                        {"id": "joeuser", "event": "updated"},
                        # {"id": "5678", "event": "created"},
                    ],
                },
            },
        ),
    ],
)
def test_webhook_post(
    # client,
    app,
    payload,
    admin,
    callback_responses,
    resp_code,
    resp_data,
    user_factory,
    db,
    search_clear,
    requests_mock,
    celery_worker,
):
    """Test webhook."""
    # with app.app_context():
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    with app.test_client() as client:
        for key, value in callback_responses.items():
            for v in value:
                headers["Authorization"] = f"Bearer {admin.allowed_token}"
                if key == "users":
                    user_factory(
                        email=v["email"],
                        oauth_src="cilogon",
                        oauth_id=v["username"],
                        kc_username=v["username"],
                        new_remote_data=v,
                    )

        app.logger.debug(f"admin roles: {admin.user.roles}")
        response = client.post(
            url_for(
                "invenio_remote_user_data_kcworks.remote_user_data_kcworks_webhook",
            ),
            data=json.dumps(payload),
            headers=headers,
        )

        app.logger.debug(json.loads(response.data))
        assert response.status_code == resp_code
        assert json.loads(response.data) == resp_data

        for key, value in callback_responses.items():
            if key == "users":
                for v in value:
                    # myuser = current_users.search(
                    #     system_identity, q=f"email:{v['email']}"
                    # ).to_dict()["hits"]["hits"]
                    db.session.expire_all()
                    myuser = current_accounts.datastore.find_user(email=v["email"])
                    app.logger.debug(f"myuser: {myuser}")
                    assert myuser.email == v["email"]
                    assert myuser.user_profile["full_name"] == v["name"]
                    assert (
                        myuser.user_profile["affiliations"]
                        == (v["institutional_affiliation"])
                    )
                    assert json.loads(myuser.user_profile["name_parts"]) == {
                        "first": v["first_name"],
                        "last": v["last_name"],
                    }
                    assert myuser.user_profile["identifier_orcid"] == (v["orcid"])

                    user_roles = [r.name for r in myuser.roles]
                    for g in user_roles:
                        groupid = g.split("---")[1].split("|")[0]
                        group_roles = GroupRolesService(
                            RemoteUserDataService
                        ).get_roles_for_remote_group(groupid, "knowledgeCommons")
                        assert (
                            len([r for r in group_roles if r.name in user_roles]) == 1
                        )
