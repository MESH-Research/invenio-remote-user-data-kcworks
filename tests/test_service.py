import arrow
import pytest
from flask import g
from flask_security import login_user, logout_user
from invenio_access.permissions import system_identity
from invenio_accounts.models import UserIdentity
from invenio_accounts.proxies import current_accounts
from invenio_accounts.testutils import login_user_via_session
from invenio_users_resources.proxies import current_users_service
from invenio_utilities_tuw.utils import get_identity_for_user
from invenio_remote_user_data.components.groups import (
    GroupsComponent,
)
from invenio_remote_user_data.proxies import (
    current_remote_user_data_service as user_service,
)
from pprint import pprint
import time


@pytest.mark.parametrize(
    "user_email,remote_id,return_payload,new_data,user_changes,"
    "new_groups,group_changes",
    [
        (
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
                    "name_parts": {
                        "first": "My",
                        "last": "User",
                    },
                    "affiliations": [{"name": "Michigan State University"}],
                    "identifiers": [
                        {
                            "identifier": "0000-0002-1825-0097",
                            "scheme": "orcid",
                        }
                    ],
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
                    "affiliations": [{"name": "Michigan State University"}],
                    "full_name": "My User",
                    "identifiers": [
                        {
                            "identifier": "0000-0002-1825-0097",
                            "scheme": "orcid",
                        }
                    ],
                    "name_parts": {"first": "My", "last": "User"},
                },
                "username": "knowledgeCommons-myuser",
            },
            [
                "knowledgeCommons|Digital Humanists|member",
                "knowledgeCommons|test bpges|admin",
            ],
            {
                "added_groups": [
                    "knowledgeCommons|Digital Humanists|member",
                    "knowledgeCommons|test bpges|admin",
                ],
                "dropped_groups": [],
                "unchanged_groups": [],
            },
        ),
    ],
)
def test_update_data_from_remote_mock(
    app,
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
):
    """Test updating user data from mocked remote API."""
    base_url = app.config["REMOTE_USER_DATA_API_ENDPOINTS"][
        "knowledgeCommons"
    ]["users"]["remote_endpoint"]
    print(base_url)

    # mock the remote api endpoint
    # requests_mock.get(f"{base_url}/{remote_id}", json=return_payload)
    requests_mock.get(
        "https://hcommons-dev.org/wp-json/commons/v1/users/myuser",
        json=return_payload,
    )

    myuser = user_factory(
        email=user_email, confirmed_at=arrow.utcnow().datetime
    )
    if not myuser.active:
        assert current_accounts.datastore.activate_user(myuser)
    UserIdentity.create(myuser, "knowledgeCommons", remote_id)

    actual = user_service.update_data_from_remote(
        myuser.id, "knowledgeCommons", remote_id
    )
    assert {
        "username": actual[0].username,
        "email": actual[0].email,
        "preferences": actual[0].preferences,
        "user_profile": actual[0].user_profile,
    } == new_data
    assert actual[1] == user_changes
    assert sorted(actual[2]) == sorted(new_groups)
    assert actual[3] == group_changes
    myuser_confirm = current_users_service.read(
        system_identity, myuser.id
    ).data
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


@pytest.mark.parametrize(
    "user_email,remote_id,new_data,user_changes,new_groups,group_changes",
    [
        (
            "thickemi@msu.edu",
            "mikethicke",
            {
                "username": "knowledgeCommons-mikethicke",
                "email": "thickemi@msu.edu",
                "user_profile": {
                    "full_name": "Mike Thicke",
                    "name_parts": {
                        "first": "Mike",
                        "last": "Thicke",
                    },
                    "affiliations": [{"name": "Michigan State University"}],
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
                    "affiliations": [{"name": "Michigan State University"}],
                    "full_name": "Mike Thicke",
                    "name_parts": {
                        "first": "Mike",
                        "last": "Thicke",
                    },
                },
                "username": "knowledgeCommons-mikethicke",
            },
            [
                "knowledgeCommons|Digital Humanists|member",
                "knowledgeCommons|test bpges|member",
                "knowledgeCommons|Public Philosophy Journal|member",
                "knowledgeCommons|MDPx|member",
                "knowledgeCommons|Science and Technology Studies (STS)|member",
                (
                    "knowledgeCommons|HC Participating Organization"
                    " Council|member"
                ),
                "knowledgeCommons|MESH|member",
                "knowledgeCommons|mla-group-test|admin",
                (
                    "knowledgeCommons|Humanities Commons User Advisory"
                    " Group|member"
                ),
                (
                    "knowledgeCommons|Humanities Commons Technical Advisory"
                    " Group|admin"
                ),
                "knowledgeCommons|ARLISNA Test Group|admin",
                "knowledgeCommons|STEMEd+ Commons Working Group|member",
                "knowledgeCommons|Test Group|member",
                "knowledgeCommons|Teaching and Learning|admin",
                "knowledgeCommons|Humanities, Arts, and Media|admin",
                "knowledgeCommons|Technology, Networks, and Sciences|admin",
                "knowledgeCommons|Social and Political Issues|admin",
                "knowledgeCommons|Educational and Cultural Institutions|admin",
                "knowledgeCommons|Publishing and Archives|admin",
                "knowledgeCommons|a new group for testing new groups|admin",
                "knowledgeCommons|Private Testing Group|admin",
                "knowledgeCommons|MSU Commons test group|admin",
            ],
            {
                "added_groups": [
                    "knowledgeCommons|Digital Humanists|member",
                    "knowledgeCommons|test bpges|member",
                    "knowledgeCommons|Public Philosophy Journal|member",
                    "knowledgeCommons|MDPx|member",
                    (
                        "knowledgeCommons|Science and Technology Studies"
                        " (STS)|member"
                    ),
                    (
                        "knowledgeCommons|HC Participating Organization"
                        " Council|member"
                    ),
                    "knowledgeCommons|MESH|member",
                    "knowledgeCommons|mla-group-test|admin",
                    (
                        "knowledgeCommons|Humanities Commons User Advisory"
                        " Group|member"
                    ),
                    (
                        "knowledgeCommons|Humanities Commons Technical"
                        " Advisory Group|admin"
                    ),
                    "knowledgeCommons|ARLISNA Test Group|admin",
                    "knowledgeCommons|STEMEd+ Commons Working Group|member",
                    "knowledgeCommons|Test Group|member",
                    "knowledgeCommons|Teaching and Learning|admin",
                    "knowledgeCommons|Humanities, Arts, and Media|admin",
                    (
                        "knowledgeCommons|Technology, Networks, and"
                        " Sciences|admin"
                    ),
                    "knowledgeCommons|Social and Political Issues|admin",
                    (
                        "knowledgeCommons|Educational and Cultural"
                        " Institutions|admin"
                    ),
                    "knowledgeCommons|Publishing and Archives|admin",
                    (
                        "knowledgeCommons|a new group for testing new"
                        " groups|admin"
                    ),
                    "knowledgeCommons|Private Testing Group|admin",
                    "knowledgeCommons|MSU Commons test group|admin",
                ],
                "dropped_groups": [],
                "unchanged_groups": [],
            },
        ),
    ],
)
def test_update_data_from_remote_live(
    app,
    user_email,
    remote_id,
    new_data,
    user_changes,
    new_groups,
    group_changes,
    user_factory,
    db,
):
    """Test updating user data from live remote API."""

    myuser = user_factory(
        email=user_email, confirmed_at=arrow.utcnow().datetime
    )
    if not myuser.active:
        assert current_accounts.datastore.activate_user(myuser)
    UserIdentity.create(myuser, "knowledgeCommons", "testuser")

    actual = user_service.update_data_from_remote(
        myuser.id, "knowledgeCommons", remote_id
    )
    assert {
        "username": actual[0].username,
        "email": actual[0].email,
        "preferences": actual[0].preferences,
        "user_profile": actual[0].user_profile,
    } == new_data
    assert actual[1] == user_changes
    assert sorted(actual[2]) == sorted(new_groups)
    assert actual[3] == group_changes
    myuser_confirm = current_users_service.read(
        system_identity, myuser.id
    ).data
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


def test_on_identity_changed(client, app, user_factory, requests_mock):
    """Test service initialization and signal triggers."""
    assert "invenio-remote-user-data" in app.extensions
    assert app.extensions["invenio-remote-user-data"].service

    # mock the remote api endpoint
    base_url = app.config["REMOTE_USER_DATA_API_ENDPOINTS"][
        "knowledgeCommons"
    ]["users"]["remote_endpoint"]
    requests_mock.get(
        f"{base_url}/testuser",
        json={"groups": [{"name": "awesome-mock"}, {"name": "admin"}]},
    )

    # mock SAML login info for the test user and add them to new groups
    myuser = user_factory(confirmed_at=arrow.utcnow().datetime)
    UserIdentity.create(myuser, "knowledgeCommons", "testuser")
    grouper = GroupsComponent(user_service)
    grouper.create_new_group(group_name="cool-group")
    grouper.create_new_group(group_name="admin")
    grouper.add_user_to_group(group_name="cool-group", user=myuser)
    grouper.add_user_to_group(group_name="admin", user=myuser)

    # log user in and check whether group memberships were updated
    login_user_via_session(client, email=myuser.email)
    # login_user(myuser)
    client.get("/api")
    my_identity = g.identity
    print(g.identity)
    print(myuser.roles)
    assert (
        len(
            [
                n.value
                for n in my_identity.provides
                if n.value
                in [
                    "admin",
                    "awesome-mock",
                    "any_user",
                    3,
                    "authenticated_user",
                ]
            ]
        )
        == 5
    )
    assert (
        len(
            [
                n.value
                for n in my_identity.provides
                if n.value
                not in [
                    "admin",
                    "awesome-mock",
                    "any_user",
                    3,
                    "authenticated_user",
                ]
            ]
        )
        == 0
    )

    # log user out and check whether group memberships were updated
    logout_user()
    time.sleep(10)
    client.get("/")
    print(dir(client))
    my_identity = g.identity
    # print(my_identity)
    assert (
        len([n.value for n in my_identity.provides if n.value in ["any_user"]])
        == 1
    )
    assert (
        len(
            [
                n.value
                for n in my_identity.provides
                if n.value not in ["any_user"]
            ]
        )
        == 0
    )

    # log a different user in without mocking SAML login (so like local)
    myuser2 = user_factory(email="another@mydomain.com")
    login_user(myuser2)
    login_user_via_session(client, email=myuser2.email)
    time.sleep(10)
    client.get("/")
    my_identity = g.identity
    print("$$$$$")
    print(g.identity)
    print(myuser2)
    print(get_identity_for_user(myuser2.email))
    assert (
        len(
            [
                n.value
                for n in my_identity.provides
                if n.value in ["any_user", 2, "authenticated_user"]
            ]
        )
        == 3
    )
    assert (
        len(
            [
                n.value
                for n in my_identity.provides
                if n.value not in ["any_user", 2, "authenticated_user"]
            ]
        )
        == 0
    )


@pytest.mark.parametrize(
    "remote_data,starting_data,new_data,user_changes,group_changes",
    [
        (
            {
                "users": {
                    "username": "myuser",
                    "email": "myaddress@hcommons.org",
                    "name": "My User",
                    "first_name": "My",
                    "last_name": "User",
                    "institutional_affiliation": "Michigan State University",
                    "orcid": "0000-0002-1825-0097",
                    "groups": [
                        {
                            "id": 1000576,
                            "name": "awesome-mock",
                            "role": "admin",
                        },
                        {
                            "id": 1000577,
                            "name": "cool-group2",
                            "role": "member",
                        },
                    ],
                },
            },
            {
                "user": {"email": "myaddress@hcommons.org"},
                "groups": [
                    {"name": "cool-group", "role": "admin"},
                    {"name": "cool-group2", "role": "member"},
                ],
            },
            {
                "active": True,
                "username": "knowledgeCommons-myuser",
                "email": "myaddress@hcommons.org",
                "user_profile": {
                    "affiliations": [{"name": "Michigan State University"}],
                    "full_name": "My User",
                    "identifiers": [
                        {
                            "identifier": "0000-0002-1825-0097",
                            "scheme": "orcid",
                        }
                    ],
                    "name_parts": {"first": "My", "last": "User"},
                },
                "preferences": {
                    "email_visibility": "restricted",
                    "visibility": "restricted",
                    "locale": "en",
                    "timezone": "Europe/Zurich",
                },
            },
            {
                "username": "knowledgeCommons-myuser",
                "user_profile": {
                    "affiliations": [{"name": "Michigan State University"}],
                    "full_name": "My User",
                    "identifiers": [
                        {
                            "identifier": "0000-0002-1825-0097",
                            "scheme": "orcid",
                        }
                    ],
                    "name_parts": {"first": "My", "last": "User"},
                },
            },
            {
                "dropped_groups": ["knowledgeCommons|cool-group|admin"],
                "added_groups": ["knowledgeCommons|awesome-mock|admin"],
                "unchanged_groups": [
                    "knowledgeCommons|cool-group2|member",
                    "admin",
                ],
            },
        )
    ],
)
def test_compare_remote_with_local(
    app,
    remote_data,
    starting_data,
    new_data,
    user_changes,
    group_changes,
    user_factory,
    db,
):
    """Test comparison of remote and local user data."""
    grouper = GroupsComponent(user_service)
    myuser = user_factory(**starting_data["user"])
    grouper.create_new_group(group_name="admin")
    grouper.add_user_to_group(group_name="admin", user=myuser)
    for group in starting_data["groups"]:
        grouper.create_new_group(
            group_name=f"knowledgeCommons|{group['name']}|{group['role']}"
        )
        grouper.add_user_to_group(
            group_name=f"knowledgeCommons|{group['name']}|{group['role']}",
            user=myuser,
        )

    (
        actual_new,
        actual_user_changes,
        actual_group_changes,
    ) = user_service.compare_remote_with_local(
        user=myuser, remote_data=remote_data, idp="knowledgeCommons"
    )
    assert actual_new == new_data
    assert actual_user_changes == user_changes
    assert actual_group_changes == group_changes


def test_update_invenio_group_memberships(app, user_factory, db):
    """Test updating invenio group memberships based on remote comparison."""
    test_changed_memberships = {
        "dropped_groups": ["cool-group"],
        "added_groups": ["awesome-mock"],
    }
    expected_updated_memberships = ["admin", "awesome-mock"]
    myuser = user_factory()
    my_identity = get_identity_for_user(myuser.email)

    # set up starting roles and memberships
    grouper = GroupsComponent(user_service)
    grouper.create_new_group(group_name="cool-group")
    grouper.create_new_group(group_name="admin")
    grouper.add_user_to_group("cool-group", myuser)
    grouper.add_user_to_group("admin", myuser)

    actual_updated_memberships = user_service.update_invenio_group_memberships(
        myuser, test_changed_memberships
    )

    assert actual_updated_memberships == expected_updated_memberships
    assert [r for r in myuser.roles] == ["admin", "awesome-mock"]
    my_identity = get_identity_for_user(myuser.email)
    assert all(
        n.value
        for n in my_identity.provides
        if n in ["admin", "awesome-mock", "any_user", 5]
    )
