"""Service-layer tests for remote user and group synchronization."""


import pytest
from invenio_access.permissions import system_identity
from invenio_accounts.models import UserIdentity
from invenio_accounts.proxies import current_accounts
from invenio_communities.communities.records.api import Community
from invenio_communities.proxies import current_communities
from invenio_group_collections_kcworks.errors import CollectionNotFoundError
from invenio_group_collections_kcworks.proxies import current_group_collections_service
from invenio_group_collections_kcworks.utils import add_user_to_community
from invenio_search import current_search_client
from invenio_search.engine import dsl
from invenio_search.utils import build_alias_name
from invenio_utilities_tuw.utils import get_identity_for_user

from invenio_remote_user_data_kcworks.proxies import (
    current_remote_group_service as group_data_service,
)
from invenio_remote_user_data_kcworks.proxies import (
    current_remote_user_data_service as user_data_service,
)
from invenio_remote_user_data_kcworks.services.group_roles import GroupRolesService
from invenio_remote_user_data_kcworks.types.profiles_api import Profile
from invenio_remote_user_data_kcworks.utils.auth import CILogonHelpers


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
                "username": "myuser",
                "email": "myaddress@hcommons.org",
                "user_profile": {
                    "affiliations": "Michigan State University",
                    "full_name": "My User",
                    "identifier_orcid": "0000-0002-1825-0097",
                    "identifier_kc_username": "myuser",
                    "name_parts": '{"first": "My", "last": "User"}',
                },
                "preferences": {
                    "email_visibility": "public",
                    "visibility": "public",
                    "locale": "en",
                    "timezone": "Europe/Zurich",
                },
            },
            {
                "user_profile": {
                    "affiliations": "Michigan State University",
                    "full_name": "My User",
                    "identifier_orcid": "0000-0002-1825-0097",
                    "name_parts": '{"first": "My", "last": "User"}',
                },
                "preferences": {
                    "visibility": "public",
                    "email_visibility": "public",
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
def test_calculate_user_and_group_changes(
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
    grouper = GroupRolesService(user_data_service)
    myuser = user_factory(**starting_data["user"]).user
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
        actual_user_changes,
        actual_new,
    ) = CILogonHelpers.calculate_user_changes(
        Profile(**{
            **remote_data["users"],
            "academic_interests": [],
            "avatar": None,
            "url": None,
            "is_superadmin": False,
            "groups": [
                {
                    "id": group["id"],
                    "group_name": group["name"],
                    "role": group["role"],
                }
                for group in remote_data["users"]["groups"]
            ],
        }),
        myuser,
    )
    actual_group_changes = CILogonHelpers.calculate_group_changes(
        Profile(**{
            **remote_data["users"],
            "academic_interests": [],
            "avatar": None,
            "url": None,
            "is_superadmin": False,
            "groups": [
                {
                    "id": group["id"],
                    "group_name": group["name"],
                    "role": group["role"],
                }
                for group in remote_data["users"]["groups"]
            ],
        }),
        myuser,
    )
    assert actual_new == new_data
    assert actual_user_changes == user_changes
    assert actual_group_changes == group_changes


def test_update_group_memberships_helper(app, user_factory, db):
    """Test updating invenio group memberships based on remote comparison."""
    test_changed_memberships = {
        "dropped_groups": ["cool-group"],
        "added_groups": ["awesome-mock"],
    }
    expected_updated_memberships = ["admin", "awesome-mock"]
    myuser = user_factory().user
    my_identity = get_identity_for_user(myuser.email)

    # set up starting roles and memberships
    grouper = GroupRolesService(user_data_service)
    grouper.create_new_group(group_name="cool-group")
    grouper.create_new_group(group_name="admin")
    grouper.add_user_to_group("cool-group", myuser)
    grouper.add_user_to_group("admin", myuser)

    actual_updated_memberships = CILogonHelpers._update_invenio_group_memberships(
        myuser, test_changed_memberships
    )

    assert actual_updated_memberships == expected_updated_memberships
    assert [r.name for r in myuser.roles] == ["admin", "awesome-mock"]
    my_identity = get_identity_for_user(myuser.email)
    assert all(
        n.value
        for n in my_identity.provides
        if n in ["admin", "awesome-mock", "any_user", 5]
    )


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
                "description": (
                    "For scholars interested in J.R.R. Tolkien, C. S. Lewis, "
                    "Charles Williams, and other writers associated with the "
                    "Inklings."
                ),
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
    """Test updating a remote group when no local community exists."""
    base_url = app.config["REMOTE_USER_DATA_API_ENDPOINTS"][idp]["groups"][
        "remote_endpoint"
    ]

    requests_mock.get(
        f"{base_url}{remote_group_id}",
        json=return_payload,
    )

    with app.app_context():
        actual = group_data_service.update_group_from_remote(
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
                    "title": "The Inklings Unedited",
                    "description": "A collection managed by the "
                    "The Inklings Unedited group of Knowledge Commons",
                    "curation_policy": "",
                    "page": "This"
                    " is a collection of works curated by the "
                    "The Inklings group of Knowledge Commons",
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
                        # Owner is a group, not a user
                        "is_verified": False,
                        "slug": "the-inklings",
                        "metadata": {
                            "title": "The Inklings Unedited",
                            "description": "A collection managed by the The Inklings Unedited group of Knowledge Commons",  # noqa
                            "curation_policy": "",
                            "page": (
                                "This is a collection of works curated by the "
                                "The Inklings group of Knowledge Commons"
                            ),
                            "website": "https://hcommons-dev.org/groups/the-inklings/",  # noqa
                            "organizations": [
                                {"name": "The Inklings"},
                                {"name": "Knowledge Commons"},
                            ],
                        },
                        "access": {
                            "visibility": "public",
                            "members_visibility": "public",
                            "member_policy": "closed",
                            "record_submission_policy": "open",
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
    running_app,
    idp,
    remote_group_id,
    creation_data,
    return_payload,
    group_role_changes,
    db,
    location,
    requests_mock,
    search_clear,
):
    """Note that the group title and description are *not* updated.

    the remote group data because these may have been edited locally.
    """
    app = running_app.app
    # mock the remote group data api endpoint
    base_url = app.config["REMOTE_USER_DATA_API_ENDPOINTS"][idp]["groups"][
        "remote_endpoint"
    ]
    requests_mock.get(
        f"{base_url}{remote_group_id}",
        json=return_payload,
    )

    # create the group collection/community in the database
    with app.app_context():
        GroupRolesService(user_data_service).create_new_group(
            group_name="administrator"
        )
        existing_collection = current_communities.service.create(
            identity=system_identity, data=creation_data
        )
        Community.index.refresh()

        communities_index = dsl.Index(
            build_alias_name(current_communities.service.config.record_cls.index._name),
            using=current_search_client,  # type: ignore
        )
        app.logger.debug(f"Communities index: {communities_index}")

        search_result = current_group_collections_service.read(
            system_identity, existing_collection["slug"]
        )
        app.logger.debug(f"Read group collection {search_result}")

        actual = group_data_service.update_group_from_remote(
            system_identity, idp, remote_group_id
        )
    expected = group_role_changes[existing_collection["slug"]]

    actual_md = {
        k: v
        for k, v in actual[existing_collection["slug"]]["metadata_updated"].items()
        if k not in ["revision_id", "created", "updated", "links", "id"]
    }
    expected_md = {
        k: v
        for k, v in expected["metadata_updated"].items()
        if k not in ["revision_id", "created", "updated", "links", "id"]
    }
    assert actual_md == expected_md

    with app.app_context():
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
        == expected["metadata_updated"]["custom_fields"]["kcr:commons_group_name"]
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
                    "title": "The Inklings Unedited",
                    "description": "A collection managed by the "
                    "The Inklings Unedited group of Knowledge Commons",
                    "curation_policy": "",
                    "page": "This"
                    " is a collection of works curated by the "
                    "The Inklings group of Knowledge Commons",
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
                        "knowledgeCommons---1004290|administrator",
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
    running_app,
    idp,
    remote_group_id,
    creation_data,
    return_payload,
    group_role_changes,
    db,
    location,
    requests_mock,
    search_clear,
):
    """Test updating a remote group when the matching community is deleted."""
    app = running_app.app
    base_url = app.config["REMOTE_USER_DATA_API_ENDPOINTS"][idp]["groups"][
        "remote_endpoint"
    ]

    requests_mock.get(
        f"{base_url}{remote_group_id}",
        json=return_payload,
    )

    with app.app_context():
        GroupRolesService(user_data_service).create_new_group(
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
            build_alias_name(current_communities.service.config.record_cls.index._name),
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
    with app.app_context():
        with pytest.raises(CollectionNotFoundError):
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
    with app.app_context():
        community_list = current_communities.service.search(
            system_identity, q=query_params
        )
        app.logger.debug(
            f"Community list: {[c for c in community_list.to_dict()['hits']['hits']]}"
        )

        actual = group_data_service.update_group_from_remote(
            system_identity, idp, remote_group_id
        )
        app.logger.debug(f"Actual: {actual.keys()}")

    actual_md = actual[existing_collection["slug"]]["metadata_updated"]
    expected_md = group_role_changes[existing_collection["slug"]]["metadata_updated"]
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
    """Test deleting remote group roles when no community remains."""
    grouper = GroupRolesService(user_data_service)
    grouper.create_new_group(group_name="knowledgeCommons---1004290|administrator")
    grouper.create_new_group(group_name="knowledgeCommons---1004290|member")

    fixture_user = user_factory(email=user_email)
    u = fixture_user.user
    if not u.active:
        assert current_accounts.datastore.activate_user(u)
    UserIdentity.create(u, "knowledgeCommons", "testuser")

    grouper.add_user_to_group("knowledgeCommons---1004290|administrator", user=u)
    assert [r.name for r in grouper.get_current_user_roles(u)] == [
        "knowledgeCommons---1004290|administrator"
    ]

    with app.app_context():
        actual = group_data_service.delete_group_from_remote(
            "knowledgeCommons", "1004290", "The Inklings"
        )

    assert (
        current_accounts.datastore.find_role("knowledgeCommons---1004290|administrator")
        is None
    )
    assert (
        current_accounts.datastore.find_role("knowledgeCommons---1004290|member")
        is None
    )

    db.session.expire_all()
    u = current_accounts.datastore.find_user(email=user_email)
    assert "knowledgeCommons---1004290|administrator" not in [
        r.name for r in grouper.get_current_user_roles(u)
    ]

    assert actual == {
        "disowned_communities": [],
        "deleted_roles": [
            "knowledgeCommons---1004290|member",
            "knowledgeCommons---1004290|administrator",
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
                    "title": "The Inklings Unedited",
                    "description": "A collection managed by the "
                    "The Inklings Unedited group of Knowledge Commons",
                    "curation_policy": "",
                    "page": "This"
                    " is a collection of works curated by the "
                    "The Inklings group of Knowledge Commons",
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
                        # Owner is a group, not a user
                        "is_verified": False,
                        "slug": "the-inklings",
                        "metadata": {
                            "title": "The Inklings Unedited",
                            "description": "A collection managed by the The Inklings Unedited group of Knowledge Commons",  # noqa
                            "curation_policy": "",
                            "page": (
                                "This is a collection of works curated by the "
                                "The Inklings group of Knowledge Commons"
                            ),
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
    running_app,
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
):
    """Test deleting a remote group while preserving disowned communities."""
    # mocker remote group data api endpoint
    app = running_app.app
    base_url = app.config["REMOTE_USER_DATA_API_ENDPOINTS"][idp]["groups"][
        "remote_endpoint"
    ]
    requests_mock.get(
        f"{base_url}{remote_group_id}",
        json=return_payload,
    )

    # create the group collection/community
    grouper = GroupRolesService(user_data_service)
    with app.app_context():
        grouper.create_new_group(group_name="administrator")
        existing_collection = current_group_collections_service.create(
            system_identity, remote_group_id, idp
        )
        Community.index.refresh()

        # confirm that the group collection/community and its roles were created
        search_result = current_group_collections_service.read(
            system_identity, existing_collection["slug"]
        )
    assert search_result["slug"] == existing_collection["slug"]
    role_search_result = grouper.get_roles_for_remote_group(
        "1004290", "knowledgeCommons"
    )
    assert not [
        r.name
        for r in role_search_result
        if r.name
        not in [
            "knowledgeCommons---1004290|admin",
            "knowledgeCommons---1004290|administrator",
            "knowledgeCommons---1004290|editor",
            "knowledgeCommons---1004290|member",
            "knowledgeCommons---1004290|moderator",
        ]
    ]

    # create user and add to community via group
    fixture_user = user_factory(email=user_email)
    u = fixture_user.user
    if not u.active:
        assert current_accounts.datastore.activate_user(u)
    UserIdentity.create(u, "knowledgeCommons", "testuser")

    grouper.add_user_to_group("knowledgeCommons---1004290|administrator", user=u)
    assert [r.name for r in grouper.get_current_user_roles(u)] == [
        "knowledgeCommons---1004290|administrator"
    ]
    assert len(u.roles)

    # create a second user to be an individual member
    fixture_user2 = user_factory(
        oauth_id="5678", email="second@inveniosoftware.org", kc_username="second"
    )
    u2 = fixture_user2.user
    if not u2.active:
        assert current_accounts.datastore.activate_user(u2)
    added_member = add_user_to_community(
        str(u2.id), "reader", existing_collection["id"]
    )
    assert added_member is not None

    # ****** perform the delete operation ******
    with app.app_context():
        actual = group_data_service.delete_group_from_remote(
            "knowledgeCommons", "1004290", "The Inklings"
        )

    # confirm that the group roles were deleted
    assert (
        current_accounts.datastore.find_role("knowledgeCommons---1004290|administrator")
        is None
    )
    assert (
        current_accounts.datastore.find_role("knowledgeCommons---1004290|member")
        is None
    )

    # confirm that the user was removed from the group
    db.session.expire_all()
    u = current_accounts.datastore.find_user(email=user_email)
    assert "knowledgeCommons---1004290|administrator" not in [
        r.name for r in grouper.get_current_user_roles(u)
    ]

    # confirm that the user is an individual member of the community
    with app.app_context():
        user_memberships = current_communities.service.members.read_memberships(u)
    app.logger.debug(f"User memberships: {user_memberships}")
    assert existing_collection["id"] in [m[0] for m in user_memberships["memberships"]]

    # confirm that the other individual member is still a member of
    # the community
    with app.app_context():
        user2_memberships = current_communities.service.members.read_memberships(u2)
    assert existing_collection["id"] in [m[0] for m in user2_memberships["memberships"]]

    # confirm that the community no longer has the group info
    with app.app_context():
        final_collection_state = current_group_collections_service.read(
            system_identity, existing_collection["slug"]
        )
    assert final_collection_state["custom_fields"]["kcr:commons_group_id"] == ""
    assert final_collection_state["custom_fields"]["kcr:commons_group_name"] == ""
    assert (
        final_collection_state["custom_fields"]["kcr:commons_group_description"] == ""
    )
    assert final_collection_state["custom_fields"]["kcr:commons_group_visibility"] == ""

    # confirm that the return value reporting the operations is correct
    assert actual["disowned_communities"] == [existing_collection["slug"]]
    assert sorted(actual["deleted_roles"]) == sorted(
        [
            "knowledgeCommons---1004290|admin",
            "knowledgeCommons---1004290|administrator",
            "knowledgeCommons---1004290|editor",
            "knowledgeCommons---1004290|member",
            "knowledgeCommons---1004290|moderator",
        ]
    )
