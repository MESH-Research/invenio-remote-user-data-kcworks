import pytest
import requests
import json
import os
from invenio_remote_user_data.utils import logger

# import requests


def test_webhook_get(client, app):
    """Test webhook."""
    response = client.get("/api/webhooks/idp_data_update")

    print(response.data)

    assert response.status_code == 200
    assert json.loads(response.data) == {
        "message": "Webhook receiver is active",
        "status": 200,
    }


@pytest.mark.parametrize(
    "token,payload,resp_code,resp_data",
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
            401,
            {},
        ),
        (
            os.getenv("REMOTE_USER_DATA_WEBHOOK_TOKEN"),
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
            202,
            {"message": "Webhook received", "status": 202},
        ),
    ],
)
def test_webhook_post(
    client, app, payload, admin, token, resp_code, resp_data, db
):
    """Test webhook."""

    from invenio_oauth2server.models import Token

    token_actual = Token.create_personal(
        "webhook", admin.id, scopes=[], is_internal=False
    )
    db.session.commit()
    # logger.info(f"token_actual: {token_actual.client_id}")

    headers = {"Authorization": f"Bearer {token_actual.client_id}"}

    response = client.post(
        "/api/webhooks/idp_data_update",
        json=payload,
        headers=headers,
    )

    print(json.loads(response.data))
    assert response.status_code == resp_code
    assert json.loads(response.data) == resp_data
