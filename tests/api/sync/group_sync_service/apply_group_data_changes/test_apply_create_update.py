# Part of invenio-remote-user-data-kcworks
# Copyright (C) 2023-2026, MESH Research
#
# invenio-remote-user-data-kcworks is free software; you can redistribute and/or
# modify it under the terms of the MIT License; see LICENSE file for more details.

"""Apply remote group create/update onto local roles and communities.

Service-side apply for `update_group_from_remote` when Profiles reports a
group create/update. Webhook enqueue ownership stays under
`on_webhook_sync_signal/test_sync_job_dispatch.py`. Delete paths live in
`test_apply_delete.py`. Local role helpers live under
`api/helper_services/group_roles/`.

Covers:

- Create/update local group roles and linked communities when they exist,
  don’t, or were deleted.
"""

import pytest
from invenio_access.permissions import system_identity
from invenio_communities.communities.records.api import Community
from invenio_communities.proxies import current_communities
from invenio_group_collections_kcworks.errors import CollectionNotFoundError
from invenio_group_collections_kcworks.proxies import current_group_collections_service
from invenio_search import current_search_client
from invenio_search.engine import dsl
from invenio_search.utils import build_alias_name

from invenio_remote_user_data_kcworks.proxies import (
    current_remote_group_service as group_data_service,
)
from invenio_remote_user_data_kcworks.proxies import (
    current_remote_user_data_service as user_data_service,
)
from invenio_remote_user_data_kcworks.services.group_roles import GroupRolesService


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
    updated = actual[existing_collection["slug"]]["metadata_updated"]
    expected_updated = expected["metadata_updated"]

    # Avoid full to_dict() equality: community dumps can include extra
    # registered custom fields (e.g. commons_search_*) absent from the fixture.
    assert updated["metadata"]["title"] == expected_updated["metadata"]["title"]
    assert (
        updated["metadata"]["description"]
        == expected_updated["metadata"]["description"]
    )
    assert updated["metadata"]["website"] == expected_updated["metadata"]["website"]
    assert (
        updated["access"]["visibility"] == expected_updated["access"]["visibility"]
    )
    group_cf_keys = (
        "kcr:commons_instance",
        "kcr:commons_group_id",
        "kcr:commons_group_name",
        "kcr:commons_group_description",
        "kcr:commons_group_visibility",
    )
    assert {k: updated["custom_fields"][k] for k in group_cf_keys} == {
        k: expected_updated["custom_fields"][k] for k in group_cf_keys
    }

    with app.app_context():
        Community.index.refresh()
        search_result = current_group_collections_service.read(
            system_identity, existing_collection["slug"]
        )
    assert (
        search_result["metadata"]["title"]
        == expected_updated["metadata"]["title"]
    )
    assert (
        search_result["metadata"]["description"]
        == expected_updated["metadata"]["description"]
    )
    assert (
        search_result["metadata"]["website"]
        == expected_updated["metadata"]["website"]
    )
    assert (
        search_result["custom_fields"]["kcr:commons_group_name"]
        == expected_updated["custom_fields"]["kcr:commons_group_name"]
    )
    assert (
        search_result["custom_fields"]["kcr:commons_group_description"]
        == expected_updated["custom_fields"]["kcr:commons_group_description"]
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


