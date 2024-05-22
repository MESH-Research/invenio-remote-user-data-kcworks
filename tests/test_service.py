import arrow
import pytest
from flask import g
from flask_security import login_user, logout_user
from invenio_access.permissions import system_identity
from invenio_accounts.models import UserIdentity
from invenio_accounts.proxies import current_accounts
from invenio_accounts.testutils import login_user_via_session
from invenio_communities.proxies import current_communities
from invenio_communities.communities.records.api import Community
from invenio_group_collections.proxies import current_group_collections_service
from invenio_group_collections.utils import add_user_to_community
from invenio_search import current_search_client
from invenio_search.engine import dsl
from invenio_search.utils import build_alias_name
from invenio_users_resources.proxies import current_users_service
from invenio_utilities_tuw.utils import get_identity_for_user
from invenio_remote_user_data.components.groups import (
    GroupRolesComponent,
)
from invenio_remote_user_data.proxies import (
    current_remote_user_data_service as user_service,
    current_remote_group_data_service as group_service,
)
from pprint import pprint
import time
from werkzeug.exceptions import NotFound


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
                    {"id": 1000570, "name": "cool-group", "role": "admin"},
                    {"id": 1000577, "name": "cool-group2", "role": "member"},
                ],
            },
            {
                "active": True,
                "username": "knowledgeCommons-myuser",
                "email": "myaddress@hcommons.org",
                "user_profile": {
                    "affiliations": "Michigan State University",
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
                    "affiliations": "Michigan State University",
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
                "dropped_groups": ["knowledgeCommons---1000570|admin"],
                "added_groups": ["knowledgeCommons---1000576|admin"],
                "unchanged_groups": [
                    "admin",
                    "knowledgeCommons---1000577|member",
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
    grouper = GroupRolesComponent(user_service)
    myuser = user_factory(**starting_data["user"])
    grouper.create_new_group(group_name="admin")
    grouper.add_user_to_group(group_name="admin", user=myuser)
    for group in starting_data["groups"]:
        grouper.create_new_group(
            group_name=f"knowledgeCommons---{group['id']}|{group['role']}"
        )
        grouper.add_user_to_group(
            group_name=f"knowledgeCommons---{group['id']}|{group['role']}",
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
    grouper = GroupRolesComponent(user_service)
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
                    "affiliations": "Michigan State University",
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
                    "full_name": "My User",
                    "name_parts": {"first": "My", "last": "User"},
                    "identifiers": [
                        {
                            "identifier": "0000-0002-1825-0097",
                            "scheme": "orcid",
                        }
                    ],
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
def test_update_user_from_remote_mock(
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
    search_clear,
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

    if "groups" in return_payload.keys():
        for group in return_payload["groups"]:
            requests_mock.get(
                f"https://hcommons-dev.org/wp-json/commons/v1/groups/"
                f"{group['id']}",
                json={
                    "id": group["id"],
                    "name": group["name"],
                    "upload_roles": ["member", "moderator", "administrator"],
                    "moderate_roles": ["moderator", "administrator"],
                },
            )

    myuser = user_factory(
        email=user_email, confirmed_at=arrow.utcnow().datetime
    )
    if not myuser.active:
        assert current_accounts.datastore.activate_user(myuser)
    UserIdentity.create(myuser, "knowledgeCommons", remote_id)

    actual = user_service.update_user_from_remote(
        system_identity, myuser.id, "knowledgeCommons", remote_id
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
    "idp,remote_group_id,return_payload,group_role_changes",
    [
        (
            "knowledgeCommons",
            "1004290",
            {
                "id": 1004290,
                "name": "The Inklings",
                "url": "https://hcommons-dev.org/groups/the-inklings/",
                "visibility": "public",
                "description": "For scholars interested in J.R.R. Tolkien, C. S. Lewis, Charles Williams, and other writers associated with the Inklings.",
                "avatar": "https://hcommons-dev.org/app/plugins/buddypress/bp-core/images/mystery-group.png",
                "groupblog": "",
                "upload_roles": ["member", "moderator", "administrator"],
                "moderate_roles": ["moderator", "administrator"],
            },
            None,
        )
    ],
)
def test_update_group_from_remote_mock_new(
    app,
    idp,
    remote_group_id,
    return_payload,
    group_role_changes,
    db,
    requests_mock,
    search_clear,
):

    base_url = app.config["REMOTE_USER_DATA_API_ENDPOINTS"][idp]["groups"][
        "remote_endpoint"
    ]

    requests_mock.get(
        f"{base_url}{remote_group_id}",
        json=return_payload,
    )

    actual = group_service.update_group_from_remote(
        system_identity, idp, remote_group_id
    )

    assert actual == group_role_changes


@pytest.mark.parametrize(
    "idp,remote_group_id,creation_data,return_payload,group_role_changes",
    [
        (
            "knowledgeCommons",
            "1004290",
            {
                "access": {
                    "visibility": "restricted",
                    "member_policy": "closed",
                    "record_policy": "closed",
                },
                "slug": "the-inklings",
                "metadata": {
                    "title": f"The Inklings Unedited",
                    "description": f"A collection managed by the "
                    f"The Inklings Unedited group of Knowledge Commons",
                    "curation_policy": "",
                    "page": f"This"
                    " is a collection of works curated by the "
                    f"The Inklings group of Knowledge Commons",
                    "website": "https://theinklings.org",
                    "organizations": [
                        {
                            "name": "The Inklings",
                        },
                        {"name": "Knowledge Commons"},
                    ],
                },
                "custom_fields": {
                    "kcr:commons_instance": "knowledgeCommons",
                    "kcr:commons_group_id": "1004290",
                    "kcr:commons_group_name": "The Inklings Unedited",
                    "kcr:commons_group_description": "",  # noqa: E501
                    "kcr:commons_group_visibility": "public",  # noqa: E501
                },
            },
            {
                "id": "1004290",
                "name": "The Inklings",
                "url": "https://hcommons-dev.org/groups/the-inklings/",
                "visibility": "public",
                "description": "For scholars interested in J.R.R. Tolkien, C. S. Lewis, Charles Williams, and other writers associated with the Inklings.",  # noqa
                "avatar": "",  # avoid testing file operations here
                "groupblog": "",
                "upload_roles": ["member", "moderator", "administrator"],
                "moderate_roles": ["moderator", "administrator"],
            },
            {
                "the-inklings": {
                    "metadata_updated": {
                        "id": "55d2af81-fa4e-4ac0-866f-a8d99c333c6d",
                        "created": "2024-05-03T23:48:46.312644+00:00",
                        "updated": "2024-05-03T23:48:46.536669+00:00",
                        "links": {
                            "featured": "https://127.0.0.1:5000/api/communities/55d2af81-fa4e-4ac0-866f-a8d99c333c6d/featured",  # noqa
                            "self": "https://127.0.0.1:5000/api/communities/55d2af81-fa4e-4ac0-866f-a8d99c333c6d",  # noqa
                            "self_html": "https://127.0.0.1:5000/communities/knowledgeCommons---1004290",  # noqa
                            "settings_html": "https://127.0.0.1:5000/communities/knowledgeCommons---1004290/settings",  # noqa
                            "logo": "https://127.0.0.1:5000/api/communities/55d2af81-fa4e-4ac0-866f-a8d99c333c6d/logo",  # noqa
                            "rename": "https://127.0.0.1:5000/api/communities/55d2af81-fa4e-4ac0-866f-a8d99c333c6d/rename",  # noqa
                            "members": "https://127.0.0.1:5000/api/communities/55d2af81-fa4e-4ac0-866f-a8d99c333c6d/members",  # noqa
                            "public_members": "https://127.0.0.1:5000/api/communities/55d2af81-fa4e-4ac0-866f-a8d99c333c6d/members/public",  # noqa
                            "invitations": "https://127.0.0.1:5000/api/communities/55d2af81-fa4e-4ac0-866f-a8d99c333c6d/invitations",  # noqa
                            "requests": "https://127.0.0.1:5000/api/communities/55d2af81-fa4e-4ac0-866f-a8d99c333c6d/requests",
                            "records": "https://127.0.0.1:5000/api/communities/55d2af81-fa4e-4ac0-866f-a8d99c333c6d/records",  # noqa
                        },
                        "revision_id": 3,
                        "slug": "the-inklings",
                        "metadata": {
                            "title": "The Inklings Unedited",
                            "description": "A collection managed by the The Inklings Unedited group of Knowledge Commons",  # noqa
                            "curation_policy": "",
                            "page": "This is a collection of works curated by the The Inklings group of Knowledge Commons",
                            "website": "https://hcommons-dev.org/groups/the-inklings/",  # noqa
                            "organizations": [
                                {"name": "The Inklings"},
                                {"name": "Knowledge Commons"},
                            ],
                        },
                        "access": {
                            "visibility": "restricted",
                            "members_visibility": "public",
                            "member_policy": "closed",
                            "record_policy": "closed",
                            "review_policy": "closed",
                        },
                        "custom_fields": {
                            "kcr:commons_instance": "knowledgeCommons",
                            "kcr:commons_group_id": "1004290",
                            "kcr:commons_group_name": "The Inklings",
                            "kcr:commons_group_description": "For scholars interested in J.R.R. Tolkien, C. S. Lewis, Charles Williams, and other writers associated with the Inklings.",  # noqa
                            "kcr:commons_group_visibility": "public",
                        },
                        "deletion_status": {
                            "is_deleted": False,
                            "status": "P",
                        },
                        "children": {"allow": False},
                    },
                }
            },
        )
    ],
)
def test_update_group_from_remote_with_community(
    app,
    idp,
    remote_group_id,
    creation_data,
    return_payload,
    group_role_changes,
    db,
    location,
    requests_mock,
    search_clear,
    custom_fields,
):
    """Note that the group title and description are *not* updated from
    the remote group data because these may have been edited locally.
    """
    # mock the remote group data api endpoint
    base_url = app.config["REMOTE_USER_DATA_API_ENDPOINTS"][idp]["groups"][
        "remote_endpoint"
    ]
    requests_mock.get(
        f"{base_url}{remote_group_id}",
        json=return_payload,
    )

    # create the group collection/community in the database
    GroupRolesComponent(user_service).create_new_group(
        group_name="administrator"
    )
    existing_collection = current_communities.service.create(
        identity=system_identity, data=creation_data
    )
    Community.index.refresh()

    communities_index = dsl.Index(
        build_alias_name(
            current_communities.service.config.record_cls.index._name
        ),
        using=current_search_client,  # type: ignore
    )
    app.logger.debug(f"Communities index: {communities_index}")

    search_result = current_group_collections_service.read(
        system_identity, existing_collection["slug"]
    )
    app.logger.debug(f"Read group collection {search_result}")

    actual = group_service.update_group_from_remote(
        system_identity, idp, remote_group_id
    )
    expected = group_role_changes[existing_collection["slug"]]

    actual_md = {
        k: v
        for k, v in actual[existing_collection["slug"]][
            "metadata_updated"
        ].items()
        if k not in ["revision_id", "created", "updated", "links", "id"]
    }
    expected_md = {
        k: v
        for k, v in expected["metadata_updated"].items()
        if k not in ["revision_id", "created", "updated", "links", "id"]
    }
    assert actual_md == expected_md

    Community.index.refresh()
    search_result = current_group_collections_service.read(
        system_identity, existing_collection["slug"]
    )
    assert (
        search_result["metadata"]["title"]
        == expected["metadata_updated"]["metadata"]["title"]
    )
    assert (
        search_result["metadata"]["description"]
        == expected["metadata_updated"]["metadata"]["description"]
    )
    assert (
        search_result["metadata"]["website"]
        == expected["metadata_updated"]["metadata"]["website"]
    )
    assert (
        search_result["custom_fields"]["kcr:commons_group_name"]
        == expected["metadata_updated"]["custom_fields"][
            "kcr:commons_group_name"
        ]
    )
    assert (
        search_result["custom_fields"]["kcr:commons_group_description"]
        == expected["metadata_updated"]["custom_fields"][
            "kcr:commons_group_description"
        ]
    )


@pytest.mark.parametrize(
    "idp,remote_group_id,creation_data,return_payload,group_role_changes",
    [
        (
            "knowledgeCommons",
            "1004290",
            {
                "access": {
                    "visibility": "restricted",
                    "member_policy": "closed",
                    "record_policy": "closed",
                },
                "slug": "the-inklings",
                "metadata": {
                    "title": f"The Inklings Unedited",
                    "description": f"A collection managed by the "
                    f"The Inklings Unedited group of Knowledge Commons",
                    "curation_policy": "",
                    "page": f"This"
                    " is a collection of works curated by the "
                    f"The Inklings group of Knowledge Commons",
                    "website": "https://theinklings.org",
                    "organizations": [
                        {
                            "name": "The Inklings",
                        },
                        {"name": "Knowledge Commons"},
                    ],
                },
                "custom_fields": {
                    "kcr:commons_instance": "knowledgeCommons",
                    "kcr:commons_group_id": "1004290",
                    "kcr:commons_group_name": "The Inklings Unedited",
                    "kcr:commons_group_description": "",  # noqa: E501
                    "kcr:commons_group_visibility": "public",  # noqa: E501
                },
            },
            {
                "id": "1004290",
                "name": "The Inklings",
                "url": "https://hcommons-dev.org/groups/the-inklings/",
                "visibility": "public",
                "description": "For scholars interested in J.R.R. Tolkien, C. S. Lewis, Charles Williams, and other writers associated with the Inklings.",  # noqa
                "avatar": "",  # avoid testing file operations here
                "groupblog": "",
                "upload_roles": ["member", "moderator", "administrator"],
                "moderate_roles": ["moderator", "administrator"],
            },
            {
                "the-inklings": {
                    "new_roles": [],
                    "existing_roles": [
                        "knowledgeCommons---1004290|admin",
                        "knowledgeCommons---1004290|member",
                        "knowledgeCommons---1004290|member",
                    ],
                    "metadata_updated": "deleted",
                },
                "the-inklings-1": {
                    "metadata_updated": "deleted",
                },
            },
        )
    ],
)
def test_update_group_from_remote_with_deleted_community(
    app,
    idp,
    remote_group_id,
    creation_data,
    return_payload,
    group_role_changes,
    db,
    location,
    requests_mock,
    search_clear,
    custom_fields,
):
    base_url = app.config["REMOTE_USER_DATA_API_ENDPOINTS"][idp]["groups"][
        "remote_endpoint"
    ]

    requests_mock.get(
        f"{base_url}{remote_group_id}",
        json=return_payload,
    )

    GroupRolesComponent(user_service).create_new_group(
        group_name="administrator"
    )

    # create the group collection/community in the database
    existing_collection = current_communities.service.create(
        identity=system_identity, data=creation_data
    )
    app.logger.debug(
        f"Created group collection {existing_collection.to_dict()['slug']}"
    )
    Community.index.refresh()

    communities_index = dsl.Index(  # noqa:F841
        build_alias_name(
            current_communities.service.config.record_cls.index._name
        ),
        using=current_search_client,  # type: ignore
    )

    search_result = current_group_collections_service.read(
        system_identity, existing_collection["slug"]
    )
    app.logger.debug(f"Read group collection {search_result}")

    delete_result = current_communities.service.delete_community(
        system_identity, existing_collection["slug"]
    )
    Community.index.refresh()
    assert delete_result.to_dict()["deletion_status"]["is_deleted"] is True
    with pytest.raises(NotFound):
        current_group_collections_service.read(
            system_identity, existing_collection["slug"]
        )
    # deleted_community = current_communities.service.search(
    #     system_identity, q=f'+slug:{existing_collection["slug"]}'
    # )
    # app.logger.debug(f"Deleted and searched community: {deleted_community}")
    query_params = (
        f"+custom_fields.kcr\:commons_instance:{idp} "  # noqa
        f"+custom_fields.kcr\:commons_group_id:"  # noqa
        f"{remote_group_id}"
    )
    community_list = current_communities.service.search(
        system_identity, q=query_params
    )
    app.logger.debug(
        f"Community list: {[c for c in community_list.to_dict()['hits']['hits']]}"
    )

    actual = group_service.update_group_from_remote(
        system_identity, idp, remote_group_id
    )
    app.logger.debug(f"Actual: {actual.keys()}")

    actual_md = actual[existing_collection["slug"]]["metadata_updated"]
    expected_md = group_role_changes[existing_collection["slug"]][
        "metadata_updated"
    ]
    assert actual_md == expected_md


@pytest.mark.parametrize(
    "user_email,remote_id,new_data",
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
        )
    ],
)
def test_delete_group_from_remote(
    app,
    user_email,
    remote_id,
    new_data,
    requests_mock,
    user_factory,
    db,
    search_clear,
):
    grouper = GroupRolesComponent(user_service)
    grouper.create_new_group(group_name="knowledgeCommons---1004290|admin")
    grouper.create_new_group(group_name="knowledgeCommons---1004290|member")

    myuser = user_factory(
        email=user_email, confirmed_at=arrow.utcnow().datetime
    )
    if not myuser.active:
        assert current_accounts.datastore.activate_user(myuser)
    UserIdentity.create(myuser, "knowledgeCommons", "testuser")

    grouper.add_user_to_group("knowledgeCommons---1004290|admin", user=myuser)
    assert grouper.get_current_user_roles(myuser) == [
        "knowledgeCommons---1004290|admin"
    ]

    actual = group_service.delete_group_from_remote(
        "knowledgeCommons", "1004290", "The Inklings"
    )

    assert (
        current_accounts.datastore.find_role(
            "knowledgeCommons---1004290|admin"
        )
        is None
    )
    assert (
        current_accounts.datastore.find_role(
            "knowledgeCommons---1004290|member"
        )
        is None
    )

    assert (
        "knowledgeCommons---1004290|admin"
        not in grouper.get_current_user_roles(myuser)
    )

    assert actual == {
        "disowned_communities": [],
        "deleted_roles": [
            "knowledgeCommons---1004290|member",
            "knowledgeCommons---1004290|admin",
        ],
    }


@pytest.mark.parametrize(
    "user_email,remote_id,new_data,idp,remote_group_id,creation_data,"
    "return_payload,group_role_changes",
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
                    {"id": 1004290, "name": "The Inklings", "role": "admin"},
                ],
            },
            "knowledgeCommons",
            "1004290",
            {
                "access": {
                    "visibility": "restricted",
                    "member_policy": "closed",
                    "record_policy": "closed",
                },
                "slug": "the-inklings",
                "metadata": {
                    "title": f"The Inklings Unedited",
                    "description": f"A collection managed by the "
                    f"The Inklings Unedited group of Knowledge Commons",
                    "curation_policy": "",
                    "page": f"This"
                    " is a collection of works curated by the "
                    f"The Inklings group of Knowledge Commons",
                    "website": "https://theinklings.org",
                    "organizations": [
                        {
                            "name": "The Inklings",
                        },
                        {"name": "Knowledge Commons"},
                    ],
                },
                "custom_fields": {
                    "kcr:commons_instance": "knowledgeCommons",
                    "kcr:commons_group_id": "1004290",
                    "kcr:commons_group_name": "The Inklings Unedited",
                    "kcr:commons_group_description": "",  # noqa: E501
                    "kcr:commons_group_visibility": "public",  # noqa: E501
                },
            },
            {
                "id": "1004290",
                "name": "The Inklings",
                "url": "https://hcommons-dev.org/groups/the-inklings/",
                "visibility": "public",
                "description": "For scholars interested in J.R.R. Tolkien, C. S. Lewis, Charles Williams, and other writers associated with the Inklings.",  # noqa
                "avatar": "",  # avoid testing file operations here
                "groupblog": "",
                "upload_roles": ["member", "moderator", "administrator"],
                "moderate_roles": ["moderator", "administrator"],
            },
            {
                "the-inklings": {
                    "metadata_updated": {
                        "id": "55d2af81-fa4e-4ac0-866f-a8d99c333c6d",
                        "created": "2024-05-03T23:48:46.312644+00:00",
                        "updated": "2024-05-03T23:48:46.536669+00:00",
                        "links": {
                            "featured": "https://127.0.0.1:5000/api/communities/55d2af81-fa4e-4ac0-866f-a8d99c333c6d/featured",  # noqa
                            "self": "https://127.0.0.1:5000/api/communities/55d2af81-fa4e-4ac0-866f-a8d99c333c6d",  # noqa
                            "self_html": "https://127.0.0.1:5000/communities/knowledgeCommons---1004290",  # noqa
                            "settings_html": "https://127.0.0.1:5000/communities/knowledgeCommons---1004290/settings",  # noqa
                            "logo": "https://127.0.0.1:5000/api/communities/55d2af81-fa4e-4ac0-866f-a8d99c333c6d/logo",  # noqa
                            "rename": "https://127.0.0.1:5000/api/communities/55d2af81-fa4e-4ac0-866f-a8d99c333c6d/rename",  # noqa
                            "members": "https://127.0.0.1:5000/api/communities/55d2af81-fa4e-4ac0-866f-a8d99c333c6d/members",  # noqa
                            "public_members": "https://127.0.0.1:5000/api/communities/55d2af81-fa4e-4ac0-866f-a8d99c333c6d/members/public",  # noqa
                            "invitations": "https://127.0.0.1:5000/api/communities/55d2af81-fa4e-4ac0-866f-a8d99c333c6d/invitations",  # noqa
                            "requests": "https://127.0.0.1:5000/api/communities/55d2af81-fa4e-4ac0-866f-a8d99c333c6d/requests",
                            "records": "https://127.0.0.1:5000/api/communities/55d2af81-fa4e-4ac0-866f-a8d99c333c6d/records",  # noqa
                        },
                        "revision_id": 3,
                        "slug": "the-inklings",
                        "metadata": {
                            "title": "The Inklings Unedited",
                            "description": "A collection managed by the The Inklings Unedited group of Knowledge Commons",  # noqa
                            "curation_policy": "",
                            "page": "This is a collection of works curated by the The Inklings group of Knowledge Commons",
                            "website": "https://hcommons-dev.org/groups/the-inklings/",  # noqa
                            "organizations": [
                                {"name": "The Inklings"},
                                {"name": "Knowledge Commons"},
                            ],
                        },
                        "access": {
                            "visibility": "restricted",
                            "members_visibility": "public",
                            "member_policy": "closed",
                            "record_policy": "closed",
                            "review_policy": "closed",
                        },
                        "custom_fields": {
                            "kcr:commons_instance": "knowledgeCommons",
                            "kcr:commons_group_id": "1004290",
                            "kcr:commons_group_name": "The Inklings",
                            "kcr:commons_group_description": "For scholars interested in J.R.R. Tolkien, C. S. Lewis, Charles Williams, and other writers associated with the Inklings.",  # noqa
                            "kcr:commons_group_visibility": "public",
                        },
                        "deletion_status": {
                            "is_deleted": False,
                            "status": "P",
                        },
                        "children": {"allow": False},
                    },
                }
            },
        )
    ],
)
def test_delete_group_from_remote_with_community(
    app,
    user_email,
    remote_id,
    new_data,
    idp,
    remote_group_id,
    creation_data,
    return_payload,
    group_role_changes,
    requests_mock,
    location,
    admin,
    user_factory,
    db,
    search_clear,
    custom_fields,
):
    # mocker remote group data api endpoint
    base_url = app.config["REMOTE_USER_DATA_API_ENDPOINTS"][idp]["groups"][
        "remote_endpoint"
    ]
    requests_mock.get(
        f"{base_url}{remote_group_id}",
        json=return_payload,
    )

    # create the group collection/community
    grouper = GroupRolesComponent(user_service)
    grouper.create_new_group(group_name="administrator")
    existing_collection = current_group_collections_service.create(
        system_identity, remote_group_id, idp
    )

    # confirm that the group collection/community and its roles were created
    search_result = current_group_collections_service.read(
        system_identity, existing_collection["slug"]
    )
    assert search_result["slug"] == existing_collection["slug"]
    role_search_result = grouper.get_roles_for_remote_group(
        "1004290", "knowledgeCommons"
    )
    assert not [
        r.id
        for r in role_search_result
        if r
        not in [
            "knowledgeCommons---1004290|admin",
            "knowledgeCommons---1004290|member",
            "knowledgeCommons---1004290|moderator",
            "knowledgeCommons---1004290|administrator",
        ]
    ]

    # create user and add to community via group
    myuser = user_factory(
        email=user_email, confirmed_at=arrow.utcnow().datetime
    )
    if not myuser.active:
        assert current_accounts.datastore.activate_user(myuser)
    UserIdentity.create(myuser, "knowledgeCommons", "testuser")

    grouper.add_user_to_group("knowledgeCommons---1004290|admin", user=myuser)
    assert grouper.get_current_user_roles(myuser) == [
        "knowledgeCommons---1004290|admin"
    ]
    assert len(myuser.roles)

    # create a second user to be an individual member
    myuser2 = user_factory()
    if not myuser2.active:
        assert current_accounts.datastore.activate_user(myuser2)
    add_user_to_community(str(myuser2.id), "reader", existing_collection["id"])
    assert len(myuser2.roles)

    # ****** perform the delete operation ******
    actual = group_service.delete_group_from_remote(
        "knowledgeCommons", "1004290", "The Inklings"
    )

    # confirm that the group roles were deleted
    assert (
        current_accounts.datastore.find_role(
            "knowledgeCommons---1004290|admin"
        )
        is None
    )
    assert (
        current_accounts.datastore.find_role(
            "knowledgeCommons---1004290|member"
        )
        is None
    )

    # confirm that the user was removed from the group
    assert (
        "knowledgeCommons---1004290|admin"
        not in grouper.get_current_user_roles(myuser)
    )

    # confirm that the user is an individual member of the community
    user_memberships = current_communities.service.members.read_memberships(
        myuser
    )
    app.logger.debug(f"User memberships: {user_memberships}")
    assert existing_collection["id"] in [
        m[0] for m in user_memberships["memberships"]
    ]

    # confirm that the other individual member is still a member of
    # the community
    user2_memberships = current_communities.service.members.read_memberships(
        myuser2
    )
    assert existing_collection["id"] in [
        m[0] for m in user2_memberships["memberships"]
    ]

    # confirm that the community no longer has the group info
    final_collection_state = current_group_collections_service.read(
        system_identity, existing_collection["slug"]
    )
    assert (
        final_collection_state["custom_fields"]["kcr:commons_group_id"] == ""
    )
    assert (
        final_collection_state["custom_fields"]["kcr:commons_group_name"] == ""
    )
    assert (
        final_collection_state["custom_fields"][
            "kcr:commons_group_description"
        ]
        == ""
    )
    assert (
        final_collection_state["custom_fields"]["kcr:commons_group_visibility"]
        == ""
    )

    # confirm that the return value reporting the operations is correct
    assert actual == {
        "disowned_communities": [existing_collection["slug"]],
        "deleted_roles": [
            "knowledgeCommons---1004290|moderator",
            "knowledgeCommons---1004290|administrator",
            "knowledgeCommons---1004290|member",
            "knowledgeCommons---1004290|admin",
        ],
    }


"""
@pytest.mark.parametrize(
    "user_email,remote_id,new_data,user_changes,new_groups,group_changes",
    [
        (
            "scottianw@signgmail.com",
            "ianscott",
            {
                "username": "knowledgeCommons-ianscott",
                "email": "scottianw@signgmail.com",
                "user_profile": {
                    "full_name": "Ian Scott",
                    "name_parts": {
                        "first": "Ian",
                        "last": "Scott",
                    },
                    "affiliations": "MESH Research, Michigan State University",
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
                    "affiliations": "MESH Research, Michigan State University",
                    "full_name": "Ian Scott",
                    "name_parts": {
                        "first": "Ian",
                        "last": "Scott",
                    },
                },
                "username": "knowledgeCommons-ianscott",
            },
            [],
            {
                "added_groups": [],
                "dropped_groups": [],
                "unchanged_groups": [],
            },
        ),
    ],
)
def test_update_user_from_remote_live(
    app,
    user_email,
    remote_id,
    new_data,
    user_changes,
    new_groups,
    group_changes,
    user_factory,
    db,
    search_clear,
):
    '''Test updating user data from live remote API.'''

    myuser = user_factory(
        email=user_email, confirmed_at=arrow.utcnow().datetime
    )
    if not myuser.active:
        assert current_accounts.datastore.activate_user(myuser)
    UserIdentity.create(myuser, "knowledgeCommons", "testuser")

    actual = user_service.update_user_from_remote(
        system_identity, myuser.id, "knowledgeCommons", remote_id
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
"""


def test_on_user_logged_in(
    client, app, db, user_factory, requests_mock, myuser
):
    """Test service initialization and signal triggers."""
    assert "invenio-remote-user-data" in app.extensions
    assert app.extensions["invenio-remote-user-data"].service

    # mock the remote api endpoint
    # base_url = app.config["REMOTE_USER_DATA_API_ENDPOINTS"][
    #     "knowledgeCommons"
    # ]["users"]["remote_endpoint"]
    requests_mock.get(
        # f"{base_url}/testuser",
        "https://hcommons-dev.org/wp-json/commons/v1/users/testuser",
        json={
            "username": "myuser",
            "email": "info@inveniosoftware.org",
            "name": "Jane User",
            "first_name": "Jane",
            "last_name": "User",
            "institutional_affiliation": "Michigan State University",
            "orcid": "123-456-7891",
            "preferred_language": "en",
            "time_zone": "UTC",
            "groups": [
                {"id": 12345, "name": "awesome-mock", "role": "admin"},
                {"id": 67891, "name": "admin", "role": "member"},
            ],
        },
    )

    # mock SAML login info for the test user and add them to new groups
    myuser1 = user_factory(confirmed_at=arrow.utcnow().datetime)
    UserIdentity.create(myuser1, "knowledgeCommons", "testuser")
    db.session.commit()
    grouper = GroupRolesComponent(user_service)
    grouper.create_new_group(group_name="knowledgeCommons---222222|admin")
    grouper.create_new_group(group_name="admin")
    grouper.add_user_to_group(
        group_name="knowledgeCommons---222222|admin", user=myuser1
    )
    grouper.add_user_to_group(group_name="admin", user=myuser1)

    # log user in and check whether group memberships were updated
    # need both login functions to log in and update client session
    assert len(myuser1.roles)
    assert login_user(myuser1)
    login_user_via_session(client, email=myuser1.email)
    client.get("/api")
    my_identity = g.identity
    # note that the user is dropped from knowledgeCommons---cool-group|admin
    # because that's a remotely managed group (idp prefix). But they are
    # not dropped from the admin group because that's a locally managed
    # group (no idp prefix).
    assert (
        len(
            [
                n.value
                for n in my_identity.provides
                if n.value
                in [
                    "knowledgeCommons---67891|member",
                    "knowledgeCommons---12345|admin",
                    "any_user",
                    myuser1.id,
                    "authenticated_user",
                    "admin",
                ]
            ]
        )
        == 6
    )
    assert (
        len(
            [
                n.value
                for n in my_identity.provides
                if n.value
                not in [
                    "knowledgeCommons---67891|member",
                    "knowledgeCommons---12345|admin",
                    "any_user",
                    myuser1.id,
                    "authenticated_user",
                    "admin",
                ]
            ]
        )
        == 0
    )

    myuser1 = current_users_service.read(system_identity, myuser1.id).data
    assert myuser1["username"] == "knowledgeCommons-myuser"
    assert myuser1["email"] == "info@inveniosoftware.org"
    assert myuser1["profile"]["full_name"] == "Jane User"
    assert myuser1["profile"]["affiliations"] == "Michigan State University"
    assert myuser1["profile"]["identifiers"] == [
        {
            "identifier": "123-456-7891",
            "scheme": "orcid",
        }
    ]
    assert myuser1["profile"]["name_parts"] == {
        "first": "Jane",
        "last": "User",
    }
    assert myuser1["preferences"]["email_visibility"] == "restricted"
    assert myuser1["preferences"]["visibility"] == "restricted"
    assert myuser1["preferences"]["locale"] == "en"
    # FIXME: Change the default timezone to UTC
    assert myuser1["preferences"]["timezone"] == "Europe/Zurich"

    # log user out and check whether group memberships were updated
    logout_user()
    with client.session_transaction() as session:
        if "user_id" in session:
            del session["user_id"]
            del session["_user_id"]
    time.sleep(10)
    client.get("/api")
    my_identity = g.identity
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
    # no request should be made for any user updates
    myuser2 = user_factory(email="anotheruser@msu.edu")
    assert myuser2.roles == []
    login_user(myuser2)
    login_user_via_session(client, email=myuser2.email)
    client.get("/api")
    my_identity = g.identity
    assert (
        len(
            [
                n.value
                for n in my_identity.provides
                if n.value in ["any_user", myuser2.id, "authenticated_user"]
            ]
        )
        == 3
    )
    assert (
        len(
            [
                n.value
                for n in my_identity.provides
                if n.value
                not in ["any_user", myuser2.id, "authenticated_user"]
            ]
        )
        == 0
    )
    assert myuser2.username is None
