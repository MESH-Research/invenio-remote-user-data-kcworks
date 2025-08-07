from pprint import pprint

import arrow
import pytest
from invenio_access.permissions import system_identity
from invenio_accounts.models import UserIdentity
from invenio_accounts.proxies import current_accounts
from invenio_users_resources.proxies import current_users_service


@pytest.mark.parametrize(
    "cmd,user_email,remote_id,return_payload,new_data,user_changes,"
    "new_groups,group_changes",
    [
        (
            "invenio user-data update myaddress@hcommons.org -e -s knowledgeCommons",  # noqa
            "myaddress@hcommons.org",
            "myuser",
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
                    {"id": 1000576, "name": "test bpges", "role": "admin"},
                ],
            },
            {
                "username": "knowledgeCommons-myuser",
                "email": "myaddress@hcommons.org",
                "user_profile": {
                    "full_name": "My User",
                    "name_parts": '{"first": "My", "last": "User", }',
                    "affiliations": "Michigan State University",
                    "identifier_orcid": "0000-0002-1825-0097",
                },
                "preferences": {
                    "email_visibility": "restricted",
                    "visibility": "restricted",
                    "locale": "en",
                    "timezone": "Europe/Zurich",
                },
            },
            {
                "user_profile": {
                    "full_name": "My User",
                    "name_parts": '{"first": "My", "last": "User"}',
                    "identifier_orcid": "0000-0002-1825-0097",
                    "affiliations": "Michigan State University",
                },
                "username": "knowledgeCommons-myuser",
            },
            [
                "knowledgeCommons---1000551|member",
                "knowledgeCommons---1000576|admin",
            ],
            {
                "added_groups": [
                    "knowledgeCommons---1000551|member",
                    "knowledgeCommons---1000576|admin",
                ],
                "dropped_groups": [],
                "unchanged_groups": [],
            },
        ),
    ],
)
def test_cli_update_one(
    cli_runner,
    app,
    cmd,
    user_email,
    remote_id,
    return_payload,
    new_data,
    user_changes,
    new_groups,
    group_changes,
    user_factory,
    db,
    requests_mock,
    search_clear,
):
    # base_url = app.config["REMOTE_USER_DATA_API_ENDPOINTS"][
    #     "knowledgeCommons"
    # ]["users"]["remote_endpoint"]

    # mock the remote api endpoint
    # requests_mock.get(f"{base_url}/{remote_id}", json=return_payload)
    requests_mock.get(
        "https://hcommons-dev.org/wp-json/commons/v1/users/myuser",
        json=return_payload,
    )

    if "groups" in return_payload.keys():
        for group in return_payload["groups"]:
            requests_mock.get(
                f"https://hcommons-dev.org/wp-json/commons/v1/groups/" f"{group['id']}",
                json={
                    "id": group["id"],
                    "name": group["name"],
                    "upload_roles": ["member", "moderator", "administrator"],
                    "moderate_roles": ["moderator", "administrator"],
                },
            )

    myuser = user_factory(email=user_email, confirmed_at=arrow.utcnow().datetime)
    if not myuser.active:
        assert current_accounts.datastore.activate_user(myuser)
    UserIdentity.create(myuser, "knowledgeCommons", remote_id)

    actual = cli_runner(cmd)
    assert {
        "username": actual[0].username,
        "email": actual[0].email,
        "preferences": actual[0].preferences,
        "user_profile": actual[0].user_profile,
    } == new_data
    assert actual[1] == user_changes
    assert sorted(actual[2]) == sorted(new_groups)
    assert actual[3] == group_changes
    myuser_confirm = current_users_service.read(system_identity, myuser.id).data
    pprint(myuser_confirm)
    assert {
        "username": myuser_confirm["username"],
        "email": myuser_confirm["email"],
        "preferences": {
            k: v
            for k, v in myuser_confirm["preferences"].items()
            if k != "notifications"
        },
        "user_profile": myuser_confirm["profile"],
    } == new_data
