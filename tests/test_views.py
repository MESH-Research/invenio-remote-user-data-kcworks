import pytest
import json
import os

# from invenio_remote_user_data.utils import logger


def test_webhook_get(client, app, search_clear):
    """Test webhook."""
    response = client.get("/api/webhooks/idp_data_update")

    assert response.status_code == 200
    assert json.loads(response.data) == {
        "message": "Webhook receiver is active",
        "status": 200,
    }


@pytest.mark.parametrize(
    "token,payload,callback_responses,resp_code,resp_data",
    [
        (
            None,
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
            401,
            {},
        ),
        (
            os.getenv("REMOTE_USER_DATA_WEBHOOK_TOKEN"),
            {
                "idp": "knowledgeCommons",
                "updates": {
                    "users": [
                        {"id": "myuser", "event": "updated"},
                    ],
                    # "groups": [{"id": "1234", "event": "deleted"}],
                },
            },
            {
                "users": [
                    {
                        "username": "myuser",
                        "email": "myaddress@hcommons.org",
                        "name": "My User",
                        "first_name": "My",
                        "last_name": "User",
                        "institutional_affiliation": "Michigan State University",
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
                "message": "Webhook received",
                "status": 202,
                "updates": {
                    "users": [
                        {"id": "1234", "event": "updated"},
                        {"id": "5678", "event": "created"},
                    ],
                    "groups": [{"id": "1234", "event": "deleted"}],
                },
            },
        ),
    ],
)
def test_webhook_post(
    client,
    app,
    payload,
    admin,
    token,
    callback_responses,
    requests_mock,
    resp_code,
    resp_data,
    db,
    search_clear,
):
    """Test webhook."""

    client = admin.login(client)

    from invenio_oauth2server.models import Token

    token_actual = Token.create_personal(
        "webhook", admin.id, scopes=[], is_internal=False
    )
    db.session.commit()
    # logger.info(f"token_actual: {token_actual.client_id}")

    headers = {
        "Authorization": f"Bearer {token_actual.client_id}",
        "content-type": "application/json",
        "accept": "application/json",
    }

    for key, value in callback_responses.items():
        for v in value:
            requests_mock.get(
                f'https://hcommons-dev.org/wp-json/commons/v1/{key}/{v["id"]}',
                json=v,
            )

    response = client.post(
        "/api/webhooks/user_data_update",
        json=payload,
        headers=headers,
    )

    print(json.loads(response.data))
    assert response.status_code == resp_code
    assert json.loads(response.data) == resp_data
